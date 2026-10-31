/// Association statistics
#[derive(Default, Debug, Copy, Clone)]
pub struct AssociationStats {
    n_datas: u64,
    n_sacks: u64,
    n_t3timeouts: u64,
    n_ack_timeouts: u64,
    n_fast_retrans: u64,
    n_loss_probes: u64,
    n_early_retrans: u64,
}

impl AssociationStats {
    pub fn inc_datas(&mut self) {
        self.n_datas += 1;
    }

    pub fn get_num_datas(&mut self) -> u64 {
        self.n_datas
    }

    pub fn inc_sacks(&mut self) {
        self.n_sacks += 1;
    }

    pub fn get_num_sacks(&mut self) -> u64 {
        self.n_sacks
    }

    pub fn inc_t3timeouts(&mut self) {
        self.n_t3timeouts += 1;
    }

    pub fn get_num_t3timeouts(&mut self) -> u64 {
        self.n_t3timeouts
    }

    pub fn inc_ack_timeouts(&mut self) {
        self.n_ack_timeouts += 1;
    }

    pub fn get_num_ack_timeouts(&mut self) -> u64 {
        self.n_ack_timeouts
    }

    pub fn inc_fast_retrans(&mut self) {
        self.n_fast_retrans += 1;
    }

    pub fn get_num_fast_retrans(&mut self) -> u64 {
        self.n_fast_retrans
    }

    pub fn inc_loss_probes(&mut self) {
        self.n_loss_probes += 1;
    }

    /// Tail loss probes sent, each retransmitting the last outstanding chunk.
    pub fn get_num_loss_probes(&mut self) -> u64 {
        self.n_loss_probes
    }

    pub fn inc_early_retrans(&mut self) {
        self.n_early_retrans += 1;
    }

    /// Chunks declared lost by RACK early retransmission in small flights.
    pub fn get_num_early_retrans(&mut self) -> u64 {
        self.n_early_retrans
    }

    pub fn reset(&mut self) {
        self.n_datas = 0;
        self.n_sacks = 0;
        self.n_t3timeouts = 0;
        self.n_ack_timeouts = 0;
        self.n_fast_retrans = 0;
        self.n_loss_probes = 0;
        self.n_early_retrans = 0;
    }
}
