use crate::CborSerializer;
use south_common::definitions::telemetry as tm;
use south_common::chell::{match_value, ChellDefinition};

macro_rules! reserializers {
    ($timestamp_ty:ty, $serializer:path, $($path:path),*) => {
        pub fn reserialize(def: &dyn ChellDefinition, timestamp: &$timestamp_ty, bytes: &[u8])
            -> Option<alloc::vec::Vec<(&'static str, alloc::vec::Vec<u8>)>> {
            use south_common::chell::_internal::InternalChellDefinition;
            use south_common::chell::ChellValue;
            use south_common::chell::ground::SerializableChellValue;
            return match_value!(def, {
                $($path => <$path as InternalChellDefinition>::ChellValueType::read(bytes)
                    .map(|v| {v.1
                        .serialize_ground(&$path, timestamp, &$serializer)
                        .ok()
                    }).ok().flatten(),
                )*
                => None
            });
        }
    }
}

reserializers!(u64, CborSerializer,
    tm::Timestamp,

    tm::lst::Uptime,
    tm::lst::Rssi,
    tm::lst::Lqi,
    tm::lst::PacketsSent,
    tm::lst::PacketsGood,
    tm::lst::PacketsRejectedChecksum,
    tm::lst::PacketsRejectedOther,

    tm::eps::SourceEnabled,
    tm::eps::SinkEnabled,
    tm::eps::InternalTemperature,
    tm::eps::AuxPowerVoltage,
    tm::eps::AuxPowerCurrent,
    tm::eps::Bat1Voltage,
    tm::eps::Bat1Temperature,
    tm::eps::Bat1Current,
    tm::eps::Bat2Voltage,
    tm::eps::Bat2Temperature,
    tm::eps::Bat2Current,

    tm::upper_sensor::imu1::Accel,
    tm::upper_sensor::imu1::Gyro,
    tm::upper_sensor::imu2::Accel,
    tm::upper_sensor::imu2::Gyro,

    tm::upper_sensor::gps::Pos,
    tm::upper_sensor::gps::Vel,
    tm::upper_sensor::gps::Status,
    
    tm::upper_sensor::Baro,
    tm::upper_sensor::InternalTemperature,

    tm::pyro::Status,
    tm::pyro::InternalTemperature,
    tm::pyro::Bat1Voltage,
    tm::pyro::Bat2Voltage,
    tm::pyro::Out1Voltage,
    tm::pyro::Out2Voltage,

    tm::lower_sensor::Adc
);


