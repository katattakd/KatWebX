// Wspx.rs handles websocket proxying.
extern crate actix;
extern crate actix_web;
extern crate futures;
extern crate bytes;

use trim_prefix;
use actix::{Actor, ActorContext, AsyncContext, Context, Handler, Arbiter, Message, StreamHandler, System, io::SinkWrite};
use actix_codec::{AsyncRead, AsyncWrite, Framed};
use actix_web_actors::ws;
use actix_web::{client::Client};
use actix_http::ws::{Codec, Frame, ProtocolError};
use bytes::Bytes;
use futures::{Future, Stream, stream::SplitSink};
use std::{thread, sync::mpsc::{Receiver, Sender, channel}, time::{Duration, Instant}};

struct WsClient<T>(SinkWrite<SplitSink<Framed<T, Codec>>>, Sender<ClientCommand>, Instant, u64)
where
    T: AsyncRead + AsyncWrite;

#[derive(Message)]
enum ClientCommand {
	Str(String),
	Bin(Bytes),
	Ping(String),
	Pong(String),
}

impl<T: 'static> Actor for WsClient<T>
where
    T: AsyncRead + AsyncWrite,
{
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Context<Self>) {
        self.hb(ctx)
    }
    fn stopped(&mut self, _: &mut Context<Self>) {
        System::current().stop();
    }
}

impl<T: 'static> WsClient<T>
where
    T: AsyncRead + AsyncWrite,
{
	fn hb(&self, ctx: &mut Context<Self>) {
		ctx.run_later(Duration::from_secs(5), |act, ctx| {
			if Instant::now().duration_since(act.2) > Duration::from_secs(act.3) {
				act.0.close();
				return;
			}
			act.hb(ctx)
		});
	}
}

impl<T: 'static> Handler<ClientCommand> for WsClient<T>
where
    T: AsyncRead + AsyncWrite,
{
    type Result = ();

    fn handle(&mut self, msg: ClientCommand, _ctx: &mut Context<Self>) {
		match msg {
			ClientCommand::Str(text) => {let _ = self.0.write(ws::Message::Text(text));},
			ClientCommand::Bin(bin) => {let _ = self.0.write(ws::Message::Binary(bin));},
			ClientCommand::Ping(msg) => {let _ = self.0.write(ws::Message::Ping(msg));},
			ClientCommand::Pong(msg) => {let _ = self.0.write(ws::Message::Pong(msg));},
		}
    }
}

impl<T: 'static> StreamHandler<Frame, ProtocolError> for WsClient<T>
where
    T: AsyncRead + AsyncWrite,
{
    fn handle(&mut self, msg: Frame, ctx: &mut Context<Self>) {
		match msg {
			Frame::Ping(msg) => {
				let _ = self.1.send(ClientCommand::Ping(msg));
				self.2 = Instant::now();
			}
			Frame::Pong(msg) => {
				let _ = self.1.send(ClientCommand::Pong(msg));
				self.2 = Instant::now();
			}
			Frame::Text(text) => {
				let _ = self.1.send(
					ClientCommand::Str(
						String::from_utf8_lossy(Bytes::from(text.unwrap()).as_ref()).into_owned()
					)
				);
			},
			Frame::Binary(bin) => {
				let _ = self.1.send(
					ClientCommand::Bin(Bytes::from(bin.unwrap()))
				);
			},
			Frame::Close(_) => {
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
			Client::new().ws(["ws", trim_prefix("http", path)].concat()).connect()
				.map_err(|e| {println!("{:?}", e);})
				.map(move |(_response, framed)| {
					let (sink, stream) = framed.split();
					let addr = WsClient::create(move |ctx| {
						WsClient::add_stream(stream, ctx);
						WsClient(SinkWrite::new(sink, ctx), sender2, Instant::now(), timeout)
					});
					thread::spawn(move || {
						for cmd in receiver1.iter() {
							addr.do_send(cmd);
						};
					});
				})
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
			ws::Message::Ping(msg) => {
				let _ = self.send.send(ClientCommand::Ping(msg));
				self.hb = Instant::now();
			}
			ws::Message::Pong(msg) => {
				let _ = self.send.send(ClientCommand::Pong(msg));
				self.hb = Instant::now();
			}
			ws::Message::Text(text) => {
				let _ = self.send.send(ClientCommand::Str(text));
			},
			ws::Message::Binary(bin) => {
				let _ = self.send.send(ClientCommand::Bin(bin));
			},
			ws::Message::Close(_) => {
				ctx.stop();
			}
			ws::Message::Nop => (),
		}
	}

	fn finished(&mut self, ctx: &mut Self::Context) {
		ctx.stop()
	}
}

impl<T: 'static> actix::io::WriteHandler<ProtocolError> for WsClient<T> where
    T: AsyncRead + AsyncWrite
{}