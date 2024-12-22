use std::net::UdpSocket;

use bitvec::prelude::*;
use bytes::{BufMut, Bytes, BytesMut};
use std::io::{copy, Write};

#[derive(Debug, Default)]
struct Header {
    /// A random ID assigned to query packets.
    /// Response packets must reply with same id.
    packet_identifier: u16,
    /// 1 for a reply packet, 0 for a question packet.
    query_response_indicator: bool,
    /// Specifies the kind of query in a message
    operation_code: u8,
    /// 1 if the server "owns" the domain queried, i.e., it's authoritative.
    authoritative_answer: bool,
    /// 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    truncation: bool,
    /// Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise
    recursion_desired: bool,
    /// Server sets this to 1 to indicate recusion is available.
    recursion_available: bool,
    /// Used by DNSSEC queries. At inception, it was reserved for future use.
    reserved: bool,
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

impl Header {
    pub fn write(self, w: &mut impl Write) -> anyhow::Result<()> {
        let mut bv = bitvec![u8, Msb0;];
        // Packet identifier
        bv.extend(self.packet_identifier.to_be_bytes());
        // Query response indicator
        bv.push(self.query_response_indicator);
        // Opcode
        for _ in 0..4 {
            bv.push(false)
        }
        // Authoritative answer
        bv.push(self.authoritative_answer);
        // Truncation
        bv.push(self.truncation);
        // Recursion desired
        bv.push(self.recursion_desired);
        // Recursion available
        bv.push(self.recursion_available);
        // Reserved
        for _ in 0..3 {
            bv.push(false)
        }
        // Response code
        for _ in 0..4 {
            bv.push(false)
        }
        // Question count
        bv.extend(self.question_count.to_be_bytes());
        // Answer record count
        bv.extend(self.answer_record_count.to_be_bytes());
        // Authority record count
        bv.extend(self.authority_record_count.to_be_bytes());
        // Additional record count
        bv.extend(self.additional_record_count.to_be_bytes());

        copy(&mut bv, w)?;
        Ok(())
    }
}

#[derive(Debug)]
struct Message {
    header: Header,
}

impl Message {
    pub fn new() -> Self {
        Self {
            header: Header {
                packet_identifier: 1234,
                query_response_indicator: true,
                question_count: 1,
                ..Default::default()
            },
        }
    }

    pub fn bytes(self) -> anyhow::Result<Bytes> {
        let bytes = BytesMut::new();
        let mut w = bytes.writer();
        self.header.write(&mut w)?;
        Ok(w.into_inner().freeze())
    }
}

fn main() -> anyhow::Result<()> {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512]; // NOTE(charlieroth): 512 bytes is the maximum size of a DNS message

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                // Construct new message and get bytes
                // - This includes the header section with values required for a response
                let b = Message::new().bytes()?;
                // Create new bytes slice from the bytes of the message
                let mut response = BytesMut::from(&b[..]);
                // QNAME
                response.put(&b"\x0ccodecrafters\x02io"[..]);
                // Null byte to end the label sequence
                response.put_u8(0u8);
                // QTYPE for A record type
                response.put_u16(1u16);
                // QCLASS for IN record class
                response.put_u16(1u16);

                // Write the response to the socket
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
            }
        }
    }
}
