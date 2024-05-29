use crate::{
    data::{IDSBatch, IDSBatcher, IDSDataset},
    model::{Model, ModelConfig},
};
use burn::{
    data::dataloader::DataLoaderBuilder, optim::AdamConfig, prelude::*, record::CompactRecorder, tensor::backend::AutodiffBackend, train::{
        metric::{AccuracyMetric, LossMetric},
        ClassificationOutput, LearnerBuilder, TrainOutput, TrainStep, ValidStep,
    }
};
use nn::loss::CrossEntropyLoss;


impl<B: Backend> Model<B> {
    pub fn forward_classification(
        &self,
        data: Tensor<B, 2>,
        targets: Tensor<B, 1, Int>,
    ) -> ClassificationOutput<B> {
        let output = self.forward(data);
        let loss = CrossEntropyLoss::new(None, &output.device()).forward(output.clone(), targets.clone());

        ClassificationOutput::new(loss, output, targets)
    }
}


impl<B: AutodiffBackend> TrainStep<IDSBatch<B>, ClassificationOutput<B>> for Model<B> {
    fn step(&self, batch: IDSBatch<B>) -> TrainOutput<ClassificationOutput<B>> {
        let item = self.forward_classification(batch.flows, batch.targets);

        TrainOutput::new(self, item.loss.backward(), item)
    }
}

impl<B: Backend> ValidStep<IDSBatch<B>, ClassificationOutput<B>> for Model<B> {
    fn step(&self, batch: IDSBatch<B>) -> ClassificationOutput<B> {
        self.forward_classification(batch.flows, batch.targets)
    }
}

#[derive(Config)]
pub struct TrainingConfig {
    pub model: ModelConfig,
    pub optimizer: AdamConfig,
    #[config(default = 3)]
    pub num_epochs: usize,
    #[config(default = 64)]
    pub batch_size: usize,
    #[config(default = 4)]
    pub num_workers: usize,
    #[config(default = 42)]
    pub seed: u64,
    #[config(default = 1.0e-4)]
    pub learning_rate: f64,
}

fn create_artifact_dir(artifact_dir: &str) {
    // Remove existing artifacts before to get an accurate learner summary
    std::fs::remove_dir_all(artifact_dir).ok();
    std::fs::create_dir_all(artifact_dir).ok();
}

pub fn train<B: AutodiffBackend>(artifact_dir: &str, config: TrainingConfig, device: B::Device) {
    create_artifact_dir(artifact_dir);
    config
        .save(format!("{artifact_dir}/config.json"))
        .expect("Config should be saved successfully");

    B::seed(config.seed);

    let batcher_train = IDSBatcher::<B>::new(device.clone());
    let batcher_valid = IDSBatcher::<B::InnerBackend>::new(device.clone());

    let dataloader_train = DataLoaderBuilder::new(batcher_train)
        .batch_size(config.batch_size)
        .shuffle(config.seed)
        .num_workers(config.num_workers)
        .build(IDSDataset::train());

    let dataloader_test = DataLoaderBuilder::new(batcher_valid)
        .batch_size(config.batch_size)
        .shuffle(config.seed)
        .num_workers(config.num_workers)
        .build(IDSDataset::test());

    let learner = LearnerBuilder::new(artifact_dir)
        .metric_train_numeric(AccuracyMetric::new())
        .metric_valid_numeric(AccuracyMetric::new())
        .metric_train_numeric(LossMetric::new())
        .metric_valid_numeric(LossMetric::new())
        .with_file_checkpointer(CompactRecorder::new())
        .devices(vec![device.clone()])
        .num_epochs(config.num_epochs)
        .summary()
        .build(
            config.model.init::<B>(&device),
            config.optimizer.init(),
            config.learning_rate,
        );

    let model_trained = learner.fit(dataloader_train, dataloader_test);

    model_trained
        .save_file(format!("{artifact_dir}/model"), &CompactRecorder::new())
        .expect("Trained model should be saved successfully");
}