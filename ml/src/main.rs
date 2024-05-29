use std::error::Error;

use ml::model::ModelConfig;
use ml::training::TrainingConfig;

use burn::{backend::{wgpu::AutoGraphicsApi, Autodiff, Wgpu}, optim::AdamConfig};


fn main() -> Result<(), Box<dyn Error>> {
    type MyBackend = Wgpu<AutoGraphicsApi, f32, i32>;
    type MyAutodiffBackend = Autodiff<MyBackend>;

    let device = burn::backend::wgpu::WgpuDevice::default();
    let artifact_dir = "./guide";
    ml::training::train::<MyAutodiffBackend>(
        artifact_dir,
        TrainingConfig::new(ModelConfig::new(5, 512, 2), AdamConfig::new()),
        device.clone(),
    );


  Ok(())
}
