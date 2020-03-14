use super::buffer::*;
use super::context::ServerContext;
use super::protocol::*;
use std::boxed::Box;
use std::io::Result;
use std::net::UdpSocket;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

type Task = Box<dyn FnOnce() + Send + 'static>;

enum Message {
    NewTask(Task),
    Terminate,
}

struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    pub fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Message>>>) -> Worker {
        let thread = thread::spawn(move || loop {
            let message = receiver
                .lock()
                .expect(format!("Worker {0} failed to acquire lock", &id).as_str())
                .recv()
                .expect(format!("Worker {0} failed to receive task from channel", &id).as_str());
            match message {
                Message::NewTask(task) => task(),
                Message::Terminate => break,
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}

struct Threadpool {
    workers: Vec<Worker>,
    transmitter: mpsc::Sender<Message>,
}

impl Threadpool {
    pub fn new(thread_count: usize) -> Threadpool {
        let (transmitter, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(thread_count);
        for i in 0..thread_count {
            workers.push(Worker::new(i, receiver.clone()));
        }

        Threadpool {
            transmitter,
            workers,
        }
    }

    pub fn execute<F>(&self, task: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let task = Box::new(task);
        self.transmitter
            .send(Message::NewTask(task))
            .expect("Failed to send task to thread pool");
    }
}

impl Drop for Threadpool {
    fn drop(&mut self) {
        println!("Received shutdown message for thread pool");

        // Send termination message to each worker
        for _ in &self.workers {
            self.transmitter.send(Message::Terminate).unwrap();
        }

        // Wait for each worker to shutdown
        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

fn execute_query(request: DnsPacket, context: Arc<ServerContext>) -> DnsPacket {
    let context_ptr = context.clone();
    let resolver = context.get_resolver(context_ptr);
    // Prepare response packet
    let mut response = DnsPacket::new();
    response.header.id = request.header.id; // question and answer must have same id
    response.header.recursion_desired = request.header.recursion_desired;
    response.header.recursion_available = context.allow_recursion;
    response.header.response = true;

    // If the request has no questions, return a FORMERR
    if request.questions.is_empty() {
        response.header.rescode = ResponseCode::FORMERR;
    } else {
        let question = &request.questions[0];
        println!("Received query: {:?}", question);

        // Now, forward the request to the downstream server
        if let Ok(result) = resolver.resolve(&question.name, question.qtype, true) {
            response.questions.push(question.clone());
            response.header.rescode = result.header.rescode;
            for rec in result.answers {
                println!("Answers: {:?}", rec);
                response.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                response.authorities.push(rec);
            }
            for rec in result.resources {
                println!("Resource: {:?}", rec);
                response.resources.push(rec);
            }
        } else {
            response.header.rescode = ResponseCode::SERVFAIL;
        }
    }

    response
}

pub trait DnsServer {
    fn run(&self, thread_count: usize) -> Result<thread::JoinHandle<()>>;
}

pub struct UdpServer {
    context: Arc<ServerContext>,
}

impl UdpServer {
    pub fn new(context: Arc<ServerContext>) -> UdpServer {
        UdpServer { context }
    }
}

impl DnsServer for UdpServer {
    fn run(&self, thread_count: usize) -> Result<thread::JoinHandle<()>> {
        let thread_pool = Threadpool::new(thread_count);
        let socket = UdpSocket::bind(("0.0.0.0", self.context.dns_port)).unwrap();
        let socket_ptr = Arc::new(Mutex::new(socket.try_clone().unwrap()));
        let context_ptr = self.context.clone();

        let udp_thread = thread::Builder::new()
            .name("DNS - UDP server worker".to_string())
            .spawn(move || {
                loop {
                    // Receive a request into a buffer
                    let mut req_buffer = BytePacketBuffer::new();
                    match socket.recv_from(&mut req_buffer.buf) {
                        Ok((_, raddr)) => {
                            let socket_clone = socket_ptr.clone();
                            let context_ptr_clone = context_ptr.clone();
                            thread_pool.execute(move || {
                                // Read DNS packet from buffer
                                let request = match DnsPacket::from_buffer(&mut req_buffer) {
                                    Ok(packet) => packet,
                                    Err(e) => {
                                        println!("Failed to parse DNS packet: {:?}", e);
                                        return;
                                    }
                                };
                                let mut response = execute_query(request, context_ptr_clone);

                                // Finally, write the response to a buffer and return to client
                                let mut res_buffer = BytePacketBuffer::new();
                                match response.write(&mut res_buffer) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        println!(
                                            "Failed to write response packet to buffer: {:?}",
                                            e
                                        );
                                        return;
                                    }
                                };

                                let res_len = res_buffer.head();
                                let res_data = match res_buffer.get_range(0, res_len) {
                                    Ok(result) => result,
                                    Err(e) => {
                                        println!("Failed to read response buffer: {:?}", e);
                                        return;
                                    }
                                };

                                match socket_clone.lock().unwrap().send_to(res_data, raddr) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        println!("Failed to send response buffer: {:?}", e);
                                        return;
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            println!("Failed to read packet: {:?}", e);
                            continue;
                        }
                    };
                }
            })?;

        Ok(udp_thread)
    }
}
