
use alloc::string::String;
use defmt::error;
use embassy_stm32::{
    can::BufferedFdCanReceiver,
};
use embassy_sync::{blocking_mutex::raw::ThreadModeRawMutex, channel::{DynamicReceiver, Sender}};
use embassy_time::Instant;

use crate::{MSG_CHANNEL_BUF_SIZE, SerializedInfo, deserialize::reserialize};

/// receive can messages and put them in the corresponding beacons
#[embassy_executor::task]
pub async fn can_receiver_task(
    can: BufferedFdCanReceiver,
    sender: Sender<'static, ThreadModeRawMutex, SerializedInfo, MSG_CHANNEL_BUF_SIZE>,
) {
    loop {
        // receive from can
        match can.receive().await {
            Ok(envelope) => {
                if let embedded_can::Id::Standard(id) = envelope.frame.id() {
                    if let Some(values) = reserialize(
                        south_common::definitions::telemetry::from_id(id.as_raw()).unwrap(),
                        &Instant::now().as_micros(),
                        envelope.frame.data()
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

/// send messages via nats
#[embassy_executor::task]
pub async fn sender_task(mut nats_client: embassy_nats::Client<'static>, receiver: DynamicReceiver<'static, SerializedInfo>) {
    loop {
        let (address, bytes) = receiver.receive().await;
        nats_client.publish(String::from(address), bytes).await;
    }
}
