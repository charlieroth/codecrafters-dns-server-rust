use std::net::UdpSocket;

struct HeaderSection {
    /// A random ID assigned to query packets.
    /// Response packets must reply with same id.
    packet_identifier: u16,
    /// 1 for a reply packet, 0 for a question packet.
    query_response_indicator: u8,
    /// Specifies the kind of query in a message
    operation_code: u8,
    /// 1 if the server "owns" the domain queried, i.e., it's authoritative.
    authoritative_answer: u8,
    /// 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    truncation: u8,
    /// Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise
    recursion_desired: u8,
    /// Server sets this to 1 to indicate recusion is available.
    recursion_available: u8,
    /// Used by DNSSEC queries. At inception, it was reserved for future use.
    reserved: u8,
    /// Response code indicating the status of the response.
    response_code: u8,
    /// Number of questions in the Question section.
    question_count: u16,
    /// Number of records in the Answer section.
    answer_record_count: u16,
    /// Number of records in the Authority section.
    authority_record_count: u16,
    /// Number of records in the Additional section.
    additional_record_count: u16,
}

impl HeaderSection {
    pub fn new() -> HeaderSection {
        HeaderSection {
            packet_identifier: 0,
            query_response_indicator: 0,
            operation_code: 0,
            authoritative_answer: 0,
            truncation: 0,
            recursion_desired: 0,
            recursion_available: 0,
            reserved: 0,
            response_code: 0,
            question_count: 0,
            answer_record_count: 0,
            authority_record_count: 0,
            additional_record_count: 0,
        }
    }

    pub fn to_response(&self) -> Vec<u8> {
        let mut response = Vec::new();
        response.push((self.packet_identifier >> 8) as u8);
        response.push(self.packet_identifier as u8);
        response.push(self.query_response_indicator);
        response.push(self.operation_code);
        response.push(self.authoritative_answer);
        response.push(self.truncation);
        response.push(self.recursion_desired);
        response.push(self.recursion_available);
        response.push(self.reserved);
        response.push(self.response_code);
        response.push((self.question_count >> 8) as u8);
        response.push(self.question_count as u8);
        response.push((self.answer_record_count >> 8) as u8);
        response.push(self.answer_record_count as u8);
        response.push((self.authority_record_count >> 8) as u8);
        response.push(self.authority_record_count as u8);
        response.push((self.additional_record_count >> 8) as u8);
        response.push(self.additional_record_count as u8);
        response
    }

    pub fn set_packet_identifier(&mut self, packet_identifier: u16) {
        self.packet_identifier = packet_identifier;
    }

    pub fn set_query_response_indicator(&mut self, query_response_indicator: u8) {
        self.query_response_indicator = query_response_indicator;
    }

    pub fn set_operation_code(&mut self, operation_code: u8) {
        self.operation_code = operation_code;
    }

    pub fn set_authoritative_answer(&mut self, authoritative_answer: u8) {
        self.authoritative_answer = authoritative_answer;
    }

    pub fn set_truncation(&mut self, truncation: u8) {
        self.truncation = truncation;
    }

    pub fn set_recursion_desired(&mut self, recursion_desired: u8) {
        self.recursion_desired = recursion_desired;
    }

    pub fn set_recursion_available(&mut self, recursion_available: u8) {
        self.recursion_available = recursion_available;
    }

    pub fn set_reserved(&mut self, reserved: u8) {
        self.reserved = reserved;
    }

    pub fn set_response_code(&mut self, response_code: u8) {
        self.response_code = response_code;
    }

    pub fn set_question_count(&mut self, question_count: u16) {
        self.question_count = question_count;
    }

    pub fn set_answer_record_count(&mut self, answer_record_count: u16) {
        self.answer_record_count = answer_record_count;
    }

    pub fn set_authority_record_count(&mut self, authority_record_count: u16) {
        self.authority_record_count = authority_record_count;
    }

    pub fn set_additional_record_count(&mut self, additional_record_count: u16) {
        self.additional_record_count = additional_record_count;
    }
}

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    // NOTE(charlieroth): 512 bytes is the maximum size of a DNS message
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let mut header = HeaderSection::new();
                header.set_packet_identifier(1234);
                header.set_query_response_indicator(1);
                let response = header.to_response();
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
