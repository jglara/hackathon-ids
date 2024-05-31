/* ,Dst Port,Total Length of Bwd Packet,Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd Packet Length Std,Bwd Packet Length Mean,Bwd Packets/s,Label */

use csv::ReaderBuilder;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct IDSItem {
    #[serde(rename = "Dst Port")]
    pub dst_port: u16,
    #[serde(rename = "Total Length of Bwd Packet")]
    pub total_length_bwd_packet: f32,
    #[serde(rename = "Bwd IAT Total")]
    pub bwd_iat_total: f32,
    #[serde(rename = "Bwd IAT Mean")]
    pub bwd_iat_mean: f32,
    #[serde(rename = "Bwd Packet Length Mean")]
    pub bwd_packet_length_mean: f32,
    #[serde(rename = "Bwd Packet Length Std")]
    pub bwd_packet_length_std: f32,
    #[serde(rename = "Label")]
    pub label: String,
}

use burn::data::dataset::{Dataset, InMemDataset};

use burn::{data::dataloader::batcher::Batcher, prelude::*};

#[derive(Clone)]
pub struct IDSBatcher<B: Backend> {
    device: B::Device,
}

impl<B: Backend> IDSBatcher<B> {
    pub fn new(device: B::Device) -> Self {
        Self { device }
    }
}

#[derive(Clone, Debug)]
pub struct IDSBatch<B: Backend> {
    pub flows: Tensor<B, 2>,
    pub targets: Tensor<B, 1, Int>,
}

impl<B: Backend> Batcher<IDSItem, IDSBatch<B>> for IDSBatcher<B> {
    fn batch(&self, items: Vec<IDSItem>) -> IDSBatch<B> {
        let flows = items
            .iter()
            .map(|item| {
                Data::<f32, 2>::from([[
                    item.total_length_bwd_packet as f32,
                    item.bwd_iat_total as f32,
                    item.bwd_iat_mean as f32,
                    item.bwd_packet_length_mean as f32,
                    item.bwd_packet_length_std as f32,
                ]])
            })
            .map(|data| Tensor::<B, 2>::from_data(data.convert(), &self.device))
            .collect();

        let targets = items
            .iter()
            .map(|item| {
                Tensor::<B, 1, Int>::from_data(
                    Data::from([(if item.label == "BENIGN" { 0 } else { 1 } as i64).elem()]),
                    &self.device,
                )
            })
            .collect();

        let flows = Tensor::cat(flows, 0).to_device(&self.device);
        let targets = Tensor::cat(targets, 0).to_device(&self.device);

        IDSBatch { flows, targets }
    }
}

pub struct IDSDataset {
    dataset: InMemDataset<IDSItem>,
}

impl IDSDataset {

    pub fn train() -> Self {
        // TODO: fix hardcoded paths
        IDSDataset {
            dataset: InMemDataset::from_csv(
                "./ml/data/train.csv",
                ReaderBuilder::new().has_headers(true),
            )
            .unwrap(),
        }
    }

    pub fn test() -> Self {
        IDSDataset {
            dataset: InMemDataset::from_csv(
                "./ml/data/test.csv",
                ReaderBuilder::new().has_headers(true),
            )
            .unwrap(),
        }
    }
}

impl Dataset<IDSItem> for IDSDataset {
    fn get(&self, index: usize) -> Option<IDSItem> {
        self.dataset.get(index)
    }

    fn len(&self) -> usize {
        self.dataset.len()
    }
}
