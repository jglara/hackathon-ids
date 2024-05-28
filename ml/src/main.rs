use std::{error::Error, fs::File, path::Path};

use csv::ReaderBuilder;

mod data;
mod model;
mod training;
mod inference;

/* 
use crate::{model::ModelConfig, training::TrainingConfig};
use burn::{
    backend::{ ndarray::NdArrayDevice, Autodiff, NdArray},
    data::dataset::Dataset,
    optim::AdamConfig,
};

fn main() {
    type MyBackend = NdArray;
    type MyAutodiffBackend = Autodiff<MyBackend>;

    let device: NdArrayDevice = Default::default();*/

use crate::{model::ModelConfig, training::TrainingConfig};
use burn::{
    backend::{wgpu::AutoGraphicsApi, Autodiff, Wgpu},
    data::dataset::Dataset,
    optim::AdamConfig,
};


fn main() -> Result<(), Box<dyn Error>> {
    type MyBackend = Wgpu<AutoGraphicsApi, f32, i32>;
    type MyAutodiffBackend = Autodiff<MyBackend>;

    let device = burn::backend::wgpu::WgpuDevice::default();
    let artifact_dir = "./guide";
    crate::training::train::<MyAutodiffBackend>(
        artifact_dir,
        TrainingConfig::new(ModelConfig::new(5, 512, 2), AdamConfig::new()),
        device.clone(),
    );


    /*crate::inference::infer::<MyBackend>(
        artifact_dir,
        device,
        burn::data::dataset::vision::MnistDataset::test()
            .get(42)
            .unwrap(),
    );*/

    /* 
  // Open the CSV file
  let path = Path::new("data/total_clean.csv");
  let file = File::open(path)?;

  // Create a CSV reader
  let mut csv_reader = ReaderBuilder::new()
      .has_headers(true)
      .from_reader(file);


  let mut items: Vec<IDSItem> = Vec::new();

  // Deserialize each record
  for result in csv_reader.deserialize::<IDSItem>() {
      let record: IDSItem = result?;

      items.push(record);
      // Process the record as needed
      
  }

  println!("{:?}", items);

  Ok(())

  */

  Ok(())
}
