use crate::{data::IDSBatcher, data::IDSItem, model::Model, training::TrainingConfig};
use burn::{
    data::dataloader::batcher::Batcher,
    prelude::*,
    record::{CompactRecorder, Recorder},
};

pub fn infer<B: Backend>(artifact_dir: &str, device: B::Device, item: IDSItem) -> i8 {
    let config = TrainingConfig::load(format!("{artifact_dir}/config.json"))
        .expect("Config should exist for the model");
    let record = CompactRecorder::new()
        .load(format!("{artifact_dir}/model").into(), &device)
        .expect("Trained model should exist");

    let model: Model<B> = config.model.init(&device).load_record(record);

    //let label = item.label.clone();
    let batcher = IDSBatcher::new(device);
    let batch = batcher.batch(vec![item]);
    let output = model.forward(batch.flows);
    let predicted = output.argmax(1).flatten::<1>(0, 1).into_scalar();

    predicted.elem()
}