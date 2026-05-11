use embassy_stm32::{
    dts::{self, Dts, FactoryCalibration},
    peripherals::DTS,
    rcc,
};

pub struct DtsDrv<'d> {
    dts: Dts<'d>,
    cal: FactoryCalibration,
    sample_time: u8,
}
impl<'d> DtsDrv<'d> {
    pub fn new(dts: Dts<'d>, sample_time: dts::SampleTime) -> Self {
        let cal = Dts::factory_calibration();
        Self {
            dts,
            cal,
            sample_time: sample_time as u8,
        }
    }
    fn convert_to_celsius(&self, raw_temp: u16) -> f32 {
        let raw_temp = raw_temp as f32;
        let sample_time = self.sample_time as f32;

        let f = rcc::frequency::<DTS>().0 as f32;

        let t0 = self.cal.t0 as f32;
        let fmt0 = self.cal.fmt0.0 as f32;
        let ramp_coeff = self.cal.ramp_coeff as f32;

        ((f * sample_time / raw_temp) - fmt0) / ramp_coeff + t0
    }

    pub async fn read(&mut self) -> f32 {
        let raw_temp = self.dts.read().await;
        let celsius = self.convert_to_celsius(raw_temp);
        celsius
    }
    //pub async fn read_tenth_deg(&mut self) -> i16 {
    //    let raw_temp = self.dts.read().await;
    //    let celsius = self.convert_to_celsius(raw_temp);
    //    (celsius * 10.) as i16
    //}
}
