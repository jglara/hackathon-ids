use burn::{
    nn::{
        Dropout, DropoutConfig, Linear, LinearConfig, Relu,
    },
    prelude::*,
};

#[derive(Module, Debug)]
pub struct Model<B: Backend> {
    linear1: Linear<B>,
    linear2: Linear<B>,
    activation1: Relu,
    dropout: Dropout,
}


#[derive(Config, Debug)]
pub struct ModelConfig {
    input_size: usize,
    hidden_size: usize,
    num_classes: usize,
    #[config(default = "0.5")]
    dropout: f64,
}

impl ModelConfig {
    /// Returns the initialized model.
    pub fn init<B: Backend>(&self, device: &B::Device) -> Model<B> {
        Model {
            activation1: Relu::new(),
            linear1: LinearConfig::new(self.input_size, self.hidden_size).init(device),
            linear2: LinearConfig::new(self.hidden_size, self.num_classes).init(device),
            dropout: DropoutConfig::new(self.dropout).init(),
        }
    }
}


impl<B: Backend> Model<B> {
    /// # Shapes
    ///   - Input [batch_size, features]
    ///   - Output [batch_size, num_classes]
    pub fn forward(&self, data: Tensor<B, 2>) -> Tensor<B, 2> {
        //let [batch_size, num_features] = data.dims();
        
        let x = self.linear1.forward(data);
        let x = self.dropout.forward(x);
        let x = self.activation1.forward(x);

        self.linear2.forward(x) // [batch_size, num_classes]
    }
}