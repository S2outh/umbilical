use alloc::string::String;
use embassy_stm32::{can::frame::FdEnvelope, exti::ExtiInput, mode::Async};
use embassy_time::{Duration, Ticker};
use south_common::{chell::{ChellDefinition, ground::SerializableChellValue}, definitions::command_msgs, obdh::OnTMFunc, types::Telecommand};

use crate::{UmbilicalChellUnion, UmbilicalComChannels, dts_drv::DtsDrv, ground_tm_defs::groundstation};

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
    com_channels: &'static UmbilicalComChannels,
    mut nats_client: embassy_nats::Client<'static>
) {
    let mut tc_counter = 0u32;
    loop {
        let nats_msg = nats_client.receive().await;
        match minicbor_serde::from_slice::<Telecommand>(&nats_msg.data) {
            Ok(cmd) => {
                tc_counter += 1;
                defmt::info!("Cmd: {}", nats_msg.data);
                let container = UmbilicalChellUnion::new(&command_msgs::Telecommand, &cmd).unwrap();
                com_channels.send_tm(container).await;

                if let Ok(values) = tc_counter.serialize_ground(
                    groundstation::umbilical::TelecommandCounter,
                    &com_channels.get_utc_us(),
                    &cbor_serializer
                ) {
                    for serialized_value in values {
                        nats_client.publish(
                            String::from(serialized_value.0),
                            serialized_value.1
                        ).await;
                    }
                }
            },
            Err(e) => defmt::warn!("could not decode cmd: {}", defmt::Debug2Format(&e)),
        }
    }
}

// internal temperature
#[embassy_executor::task]
pub async fn dts_task(
    com_channels: &'static UmbilicalComChannels,
    mut nats_client: embassy_nats::Client<'static>,
    mut dts: DtsDrv<'static>
) {
    const DTS_LOOP_LEN: Duration = Duration::from_millis(1000);
    let mut ticker = Ticker::every(DTS_LOOP_LEN);
    loop {
        let temp = dts.read().await;

        if let Ok(values) = temp.serialize_ground(
            groundstation::umbilical::InternalTemperature,
            &com_channels.get_utc_us(),
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
pub async fn launch_detection_task(com_channels: &'static UmbilicalComChannels, mut launch_detection: ExtiInput<'static, Async>) {
    loop {
        launch_detection.wait_for_rising_edge().await;
        let container = UmbilicalChellUnion::new(&command_msgs::LaunchDetected, &()).unwrap();
        com_channels.send_tm(container).await;
    }

}
