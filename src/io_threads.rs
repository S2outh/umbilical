use embassy_stm32::can::frame::FdEnvelope;
use south_common::{chell::{ChellDefinition, ChellValue}, definitions::internal_msgs, obdh::OnTMFunc, types::Telecommand};

use crate::{UmbilicalChellUnion, UmbilicalComChannels, UmbilicalTMSender};

fn cbor_serializer(
    value: &dyn erased_serde::Serialize,
) -> Result<alloc::vec::Vec<u8>, erased_serde::Error> {
    let mut buffer = alloc::vec::Vec::new();
    let mut serializer = minicbor_serde::Serializer::new(&mut buffer);
    value.erased_serialize(&mut <dyn erased_serde::Serializer>::erase(&mut serializer))?;
    Ok(buffer)
}

pub struct Reserialize {
    obdh_com_channels: &'static UmbilicalComChannels,
    nats_client: embassy_nats::Client<'static>,
}
impl Reserialize {
    pub fn new(
        obdh_com_channels: &'static UmbilicalComChannels,
        nats_client: embassy_nats::Client<'static>,
    ) -> Self {
        Self { obdh_com_channels, nats_client }
    }
}
impl OnTMFunc for Reserialize {
    async fn call(&mut self, def: &dyn ChellDefinition, envelope: &FdEnvelope) {
        if let Ok(values) = def.reserialize(
            &envelope.frame.data(),
            &self.obdh_com_channels.get_utc_us(),
            &cbor_serializer,
        ) {
            for serialized_value in values {
                self.nats_client.publish(serialized_value.0.into(), serialized_value.1).await;
            }
        }
    }
}

#[embassy_executor::task]
pub async fn telecommand_task(
    can_sender: UmbilicalTMSender,
    mut nats_client: embassy_nats::Client<'static>
) {
    let mut tc_counter = 0u32;
    loop {
        let nats_msg = nats_client.receive().await;
        if let Ok((_, cmd)) = Telecommand::read(&nats_msg.data) {
            tc_counter += 1;
            defmt::info!("Cmd: {}", nats_msg.data);
            let container = UmbilicalChellUnion::new(&internal_msgs::Telecommand, &cmd).unwrap();
            can_sender.send(container).await;
            // TODO use actual common ground serialisation (CBOR + timestamp)
            nats_client.publish(crate::ground_tm_defs::groundstation::umbilical::TelecommandCounter.address().into(), tc_counter.to_le_bytes().to_vec()).await;
        } else {
            defmt::warn!("could not decode cmd");
        }
    }
}
