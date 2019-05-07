// Wspx.rs handles websocket proxying.
extern crate actix;
extern crate actix_web;
extern crate futures;
extern crate bytes;

use trim_prefix;
use actix::*;
use actix_web::{Binary, awc::ws, awc::ws::{Client, ClientWriter, Message, ProtocolError}};
use futures::Future;
use std::{thread, sync::mpsc::{Receiver, Sender, channel}, time::{Duration, Instant}};

struct WsClient(ClientWriter, Sender<ClientCommand>, Instant, u64);

#[derive(Message)]
enum ClientCommand {
	Str(String),
	Bin(Binary),
	Ping(String),
	Pong(String),
}

impl Actor for WsClient {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Context<Self>) {
        self.hb(ctx)
    }
    fn stopped(&mut self, ctx: &mut Context<Self>) {
        ctx.stop();
    }
}

impl WsClient {
	fn hb(&self, ctx: &mut Context<Self>) {
		ctx.run_interval(Duration::from_secs(5), |act, _ctx| {
			if Instant::now().duration_since(act.2) > Duration::from_secs(act.3) {
				act.0.close(None);
				return;
			}
		});
	}
}

impl Handler<ClientCommand> for WsClient {
    type Result = ();

    fn handle(&mut self, msg: ClientCommand, _ctx: &mut Context<Self>) {
		match msg {
			ClientCommand::Str(text) => {self.0.text(text)},
			ClientCommand::Bin(bin) => {self.0.binary(bin)},
			ClientCommand::Ping(msg) => {self.0.ping(&msg)},
			ClientCommand::Pong(msg) => {self.0.pong(&msg)},
		}
    }
}

impl StreamHandler<Message, ProtocolError> for WsClient {
    fn handle(&mut self, msg: Message, ctx: &mut Self::Context) {
		match msg {
			Message::Ping(msg) => {
				let _ = self.1.send(ClientCommand::Ping(msg));
				self.2 = Instant::now();
			}
			Message::Pong(msg) => {
				let _ = self.1.send(ClientCommand::Pong(msg));
				self.2 = Instant::now();
			}
			Message::Text(text) => {let _ = self.1.send(ClientCommand::Str(text));},
			Message::Binary(bin) => {let _ = self.1.send(ClientCommand::Bin(bin));},
			Message::Close(_) => {
				ctx.stop();
			}
		}
    }

    fn finished(&mut self, ctx: &mut Context<Self>) {
        ctx.stop()
    }
}

pub struct WsProxy {
	hb: Instant,
	send: Sender<ClientCommand>,
	recv: Receiver<ClientCommand>,
	timeout: u64,
}

impl Actor for WsProxy {
	type Context = ws::WebsocketContext<Self>;
	fn started(&mut self, ctx: &mut Self::Context) {
		self.hb(ctx);
		self.hc(ctx);
	}
}

impl WsProxy {
	pub fn new(path: &str, timeout: u64) -> Self {
		let (sender1, receiver1) = channel();
		let (sender2, receiver2) = channel();

		Arbiter::spawn(
			Client::new(["ws", trim_prefix("http", path)].concat())
				.connect()
				.map_err(|e| {println!("{:?}", e)})
				.map(move |(reader, writer)| {
					let addr = WsClient::create(move |ctx| {
						WsClient::add_stream(reader, ctx);
						WsClient(writer, sender2, Instant::now(), timeout)
					});
					thread::spawn(move || {
						for cmd in receiver1.iter() {
							addr.do_send(cmd);
						};
					});
				}),
		);

		Self {
			hb: Instant::now(),
			send: sender1,
			recv: receiver2,
			timeout,
		}
	}

	fn hb(&self, ctx: &mut <Self as Actor>::Context) {
		ctx.run_interval(Duration::from_secs(5), |act, ctx| {
			if Instant::now().duration_since(act.hb) > Duration::from_secs(act.timeout) {
				ctx.stop();
				return;
			}
		});
	}
	fn hc(&self, ctx: &mut <Self as Actor>::Context) {
		ctx.run_interval(Duration::from_millis(250), |act, ctx| {
			for msg in act.recv.try_iter() {
				match msg {
					ClientCommand::Str(text) => {ctx.text(text)},
					ClientCommand::Bin(bin) => {ctx.binary(bin)},
					ClientCommand::Ping(msg) => {ctx.ping(&msg)},
					ClientCommand::Pong(msg) => {ctx.pong(&msg)},
				}
			};
		});
	}
}

impl StreamHandler<ws::Message, ws::ProtocolError> for WsProxy {
	fn handle(&mut self, msg: ws::Message, ctx: &mut Self::Context) {
        match msg {
            Message::Ping(msg) => {
				let _ = self.send.send(ClientCommand::Ping(msg));
                self.hb = Instant::now();
            }
            Message::Pong(msg) => {
				let _ = self.send.send(ClientCommand::Pong(msg));
                self.hb = Instant::now();
            }
            Message::Text(text) => {let _ = self.send.send(ClientCommand::Str(text));},
            Message::Binary(bin) => {let _ = self.send.send(ClientCommand::Bin(bin));},
            Message::Close(_) => {
                ctx.stop();
            }
        }
    }

	fn finished(&mut self, ctx: &mut Self::Context) {
		ctx.stop()
	}
}
