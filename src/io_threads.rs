use alloc::string::String;
use defmt::error;
use embassy_stm32::can::{BufferedFdCanReceiver, BufferedFdCanSender, frame::FdFrame};
use embassy_sync::{
    blocking_mutex::raw::ThreadModeRawMutex,
    channel::{DynamicReceiver, Sender},
};
use south_common::{chell::ChellDefinition, definitions::{internal_msgs, telemetry}};

use crate::{MSG_CHANNEL_BUF_SIZE, SerializedInfo, cbor_serializer, timesync::current_unix_time_micros};

/// receive can messages and put them in the corresponding beacons
#[embassy_executor::task]
pub async fn can_receiver_task(
    can: BufferedFdCanReceiver,
    unix_time_offset_us: i64,
    sender: Sender<'static, ThreadModeRawMutex, SerializedInfo, MSG_CHANNEL_BUF_SIZE>,
) {
    loop {
        // receive from can
        match can.receive().await {
            Ok(envelope) => {
                if let embedded_can::Id::Standard(id) = envelope.frame.id() {
                    let Ok(def) = telemetry::from_id(id.as_raw()) else { continue; };
                    if let Ok(values) = def.reserialize(
                        &envelope.frame.data(),
                        &current_unix_time_micros(unix_time_offset_us),
                        &cbor_serializer,
                    ) {
                        for serialized_value in values {
                            sender.send(serialized_value).await;
                        }
                    }
                } else {
                    defmt::unreachable!()
                };
            }
            Err(e) => error!("error in can frame! {}", e),
        };
    }
}

#[embassy_executor::task]
pub async fn telecommand_task(
    mut can: BufferedFdCanSender,
    mut nats_client: embassy_nats::Client<'static>
) {
    loop {
        let nats_msg = nats_client.receive().await;
        defmt::info!("Cmd: {}", nats_msg.data);
        let frame = FdFrame::new_standard(internal_msgs::Telecommand.id(), &nats_msg.data).unwrap();
        can.write(frame).await;
    }
}

/// send tm via nats
#[embassy_executor::task]
pub async fn nats_sender_task(
    mut nats_client: embassy_nats::Client<'static>,
    receiver: DynamicReceiver<'static, SerializedInfo>,
) {
    loop {
        let (address, bytes) = receiver.receive().await;
        nats_client.publish(String::from(address), bytes).await;
    }
}
