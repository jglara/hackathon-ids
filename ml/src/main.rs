use std::error::Error;

use ml::model::ModelConfig;
use ml::training::TrainingConfig;

use burn::{backend::{Autodiff, NdArray}, optim::AdamConfig};


fn main() -> Result<(), Box<dyn Error>> {
    type MyBackend = NdArray;
    type MyAutodiffBackend = Autodiff<MyBackend>;

    let device = burn::backend::ndarray::NdArrayDevice::default();
    let artifact_dir = "./ml/guide";
    ml::training::train::<MyAutodiffBackend>(
        artifact_dir,
        TrainingConfig::new(ModelConfig::new(5, 512, 2), AdamConfig::new()),
        device.clone(),
    );


  Ok(())
}
