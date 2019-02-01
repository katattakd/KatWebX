extern crate actix;
extern crate actix_web;
extern crate futures;
extern crate bytes;

use trim_prefix;
use actix::*;
use actix_web::{actix::Actor, Binary, ws, ws::{Client, ClientWriter, Message, ProtocolError}};
use futures::Future;
use std::{thread, sync::mpsc::{Receiver, Sender, channel}, time::{Duration, Instant}};

struct WsClient(ClientWriter, Sender<String>, Sender<Binary>, Instant);

#[derive(Message)]
enum ClientCommand {
	Str(String),
	Bin(Binary),
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
			if Instant::now().duration_since(act.3) > Duration::from_secs(20) {
				act.0.close(None);
				return;
			}
			act.0.ping("");
		});
	}
}

impl Handler<ClientCommand> for WsClient {
    type Result = ();

    fn handle(&mut self, msg: ClientCommand, _ctx: &mut Context<Self>) {
		match msg {
			ClientCommand::Str(text) => {self.0.text(text)},
			ClientCommand::Bin(bin) => {self.0.binary(bin)},
		}
    }
}

impl StreamHandler<Message, ProtocolError> for WsClient {
    fn handle(&mut self, msg: Message, ctx: &mut Self::Context) {
		match msg {
			Message::Ping(msg) => {
				self.3 = Instant::now();
				self.0.pong(&msg);
			}
			Message::Pong(_) => {
				self.3 = Instant::now();
			}
			Message::Text(text) => {let _ = self.1.send(text);},
			Message::Binary(bin) => {let _ = self.2.send(bin);},
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
	send_t: Sender<String>,
	recv_t: Receiver<String>,
	send_b: Sender<Binary>,
	recv_b: Receiver<Binary>,
}

impl Actor for WsProxy {
	type Context = ws::WebsocketContext<Self>;
	fn started(&mut self, ctx: &mut Self::Context) {
		self.hb(ctx);
		self.hc(ctx);
	}
}

impl WsProxy {
	pub fn new(path: &str) -> Self {
		let (sender1, receiver1) = channel();
		let (sender2, receiver2) = channel();

		let (sender3, receiver3) = channel();
		let (sender4, receiver4) = channel();

		Arbiter::spawn(
			Client::new(["ws", trim_prefix("http", path)].concat())
				.connect()
				.map_err(|e| {println!("{:?}", e)})
				.map(|(reader, writer)| {
					let addr = WsClient::create(|ctx| {
						WsClient::add_stream(reader, ctx);
						WsClient(writer, sender2, sender4, Instant::now())
					});
					thread::spawn(move || {
						for cmd in receiver1.iter() {
							addr.do_send(ClientCommand::Str(cmd));
						};
						for cmd in receiver3.iter() {
							addr.do_send(ClientCommand::Bin(cmd));
						};
					});
				}),
		);

		Self {
			hb: Instant::now(),
			send_t: sender1,
			recv_t: receiver2,
			send_b: sender3,
			recv_b: receiver4,
		}
	}

	fn hb(&self, ctx: &mut <Self as Actor>::Context) {
		ctx.run_interval(Duration::from_secs(5), |act, ctx| {
			if Instant::now().duration_since(act.hb) > Duration::from_secs(20) {
				ctx.stop();
				return;
			}
			ctx.ping("");
		});
	}
	fn hc(&self, ctx: &mut <Self as Actor>::Context) {
		ctx.run_interval(Duration::from_millis(250), |act, ctx| {
			for msg in act.recv_t.try_iter() {
				ctx.text(msg);
			};
			for msg in act.recv_b.try_iter() {
				ctx.binary(msg);
			};
		});
	}
}

impl StreamHandler<ws::Message, ws::ProtocolError> for WsProxy {
	fn handle(&mut self, msg: ws::Message, ctx: &mut Self::Context) {
        match msg {
            Message::Ping(msg) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            Message::Pong(_) => {
                self.hb = Instant::now();
            }
            Message::Text(text) => {let _ = self.send_t.send(text);},
            Message::Binary(bin) => {let _ = self.send_b.send(bin);},
            Message::Close(_) => {
                ctx.stop();
            }
        }
    }

	fn finished(&mut self, ctx: &mut Self::Context) {
		ctx.stop()
	}
}
