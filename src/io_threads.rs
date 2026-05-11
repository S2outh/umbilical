use alloc::string::String;
use embassy_stm32::{can::frame::FdEnvelope, exti::ExtiInput, mode::Async};
use embassy_time::{Duration, Ticker};
use south_common::{chell::{ChellDefinition, ground::SerializableChellValue}, definitions::internal_msgs, obdh::OnTMFunc, types::Telecommand};

use crate::{UmbilicalChellUnion, UmbilicalComChannels, UmbilicalTMSender, dts_drv::DtsDrv, ground_tm_defs::groundstation};

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
    obdh_com_channels: &'static UmbilicalComChannels,
    mut nats_client: embassy_nats::Client<'static>
) {
    let mut tc_counter = 0u32;
    let tc_counter_def = groundstation::umbilical::TelecommandCounter;
    let can_sender = obdh_com_channels.get_tm_sender();
    loop {
        let nats_msg = nats_client.receive().await;
        if let Ok(cmd) = minicbor_serde::from_slice::<Telecommand>(&nats_msg.data) {
            tc_counter += 1;
            defmt::info!("Cmd: {}", nats_msg.data);
            let container = UmbilicalChellUnion::new(&internal_msgs::Telecommand, &cmd).unwrap();
            can_sender.send(container).await;

            if let Ok(values) = tc_counter.serialize_ground(
                &tc_counter_def,
                &obdh_com_channels.get_utc_us(),
                &cbor_serializer
            ) {
                for serialized_value in values {
                    nats_client.publish(
                        String::from(serialized_value.0),
                        serialized_value.1
                    ).await;
                }
            }
        } else {
            defmt::warn!("could not decode cmd");
        }
    }
}

// internal temperature
#[embassy_executor::task]
pub async fn dts_task(
    obdh_com_channels: &'static UmbilicalComChannels,
    mut nats_client: embassy_nats::Client<'static>,
    mut dts: DtsDrv<'static>
) {
    const DTS_LOOP_LEN: Duration = Duration::from_millis(1000);
    let mut ticker = Ticker::every(DTS_LOOP_LEN);
    let temp_def = groundstation::umbilical::InternalTemperature;
    loop {
        let temp = dts.read().await;

        if let Ok(values) = temp.serialize_ground(
            &temp_def,
            &obdh_com_channels.get_utc_us(),
            &cbor_serializer
        ) {
            for serialized_value in values {
                nats_client.publish(
                    String::from(serialized_value.0),
                    serialized_value.1
                ).await;
            }
        }

        ticker.next().await;
    }
}

// Launch detection
#[embassy_executor::task]
pub async fn launch_detection_task(msg_channel: UmbilicalTMSender, mut launch_detection: ExtiInput<'static, Async>) {
    loop {
        launch_detection.wait_for_rising_edge().await;
        let container = UmbilicalChellUnion::new(&internal_msgs::LaunchDetected, &()).unwrap();
        msg_channel.send(container).await;
    }

}
