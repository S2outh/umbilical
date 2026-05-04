use alloc::string::String;
use embassy_stm32::can::frame::FdEnvelope;
use south_common::{chell::{ChellDefinition, ChellValue}, definitions::internal_msgs, obdh::OnTMFunc, types::Telecommand};

use crate::{InternalNatsReceiver, InternalNatsSender, UmbilicalChellUnion, UmbilicalComChannels, UmbilicalTMSender};

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
    nats_sender: InternalNatsSender
}
impl Reserialize {
    pub fn new(
        obdh_com_channels: &'static UmbilicalComChannels,
        nats_sender: InternalNatsSender
    ) -> Self {
        Self { obdh_com_channels, nats_sender }
    }
}
impl OnTMFunc for Reserialize {
    async fn call(&self, def: &dyn ChellDefinition, envelope: &FdEnvelope) {
        if let Ok(values) = def.reserialize(
            &envelope.frame.data(),
            &self.obdh_com_channels.get_utc_us(),
            &cbor_serializer,
        ) {
            for serialized_value in values {
                self.nats_sender.send(serialized_value).await;
            }
        }
    }
}

#[embassy_executor::task]
pub async fn telecommand_task(
    can_sender: UmbilicalTMSender,
    mut nats_client: embassy_nats::Client<'static>
) {
    loop {
        let nats_msg = nats_client.receive().await;
        if let Ok((_, cmd)) = Telecommand::read(&nats_msg.data) {
            defmt::info!("Cmd: {}", nats_msg.data);
            let container = UmbilicalChellUnion::new(&internal_msgs::Telecommand, &cmd).unwrap();
            can_sender.send(container).await;
        } else {
            defmt::warn!("could not decode cmd");
        }
    }
}

/// send tm via nats
#[embassy_executor::task]
pub async fn nats_sender_task(
    mut nats_client: embassy_nats::Client<'static>,
    receiver: InternalNatsReceiver,
) {
    loop {
        let (address, bytes) = receiver.receive().await;
        nats_client.publish(String::from(address), bytes).await;
    }
}
