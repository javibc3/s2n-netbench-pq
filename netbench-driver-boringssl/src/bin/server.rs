// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use netbench::{multiplex, scenario, Result, Timer};
use netbench_driver::Allocator;
use std::{collections::HashSet, ops::Deref, sync::Arc};
use tokio::{
    io::AsyncReadExt, net::{TcpListener, TcpStream}, spawn
};
use boring::{ssl::{SslAcceptor, SslMethod}, pkcs12::Pkcs12};

#[global_allocator]
static ALLOCATOR: Allocator = Allocator::new();

fn main() -> Result<()> {
    let args = NetbenchServer::parse();
    let runtime = args.opts.runtime();
    runtime.block_on(args.run())
}

#[derive(Debug, Parser)]
pub struct NetbenchServer {
    #[command(flatten)]
    opts: netbench_driver::Server,
}

impl NetbenchServer {
    pub async fn run(&self) -> Result<()> {
        let scenario = self.opts.scenario();
        let buffer = (*self.opts.rx_buffer as usize, *self.opts.tx_buffer as usize);

        let server = self.server().await?;

        let trace = self.opts.trace();
        let config = self.opts.multiplex();
        let acceptor = self.ssl_acceptor()?;
        let acceptor = Arc::new(acceptor);

        let mut conn_id = 0;
        loop {
            let (connection, _addr) = server.accept().await?;

            if !self.opts.nagle {
                let _ = connection.set_nodelay(true);
            }

            let scenario = scenario.clone();
            let id = conn_id;
            conn_id += 1;
            let acceptor = acceptor.clone();
            let trace = trace.clone();
            let config = config.clone();
            spawn(async move {
                if let Err(err) = handle_connection(acceptor, connection, id, scenario, trace, config, buffer).await {
                    eprintln!("error: {err}");
                }
            });
        }

        async fn handle_connection(
            acceptor: Arc<SslAcceptor>,
            connection: TcpStream,
            conn_id: u64,
            scenario: Arc<scenario::Server>,
            mut trace: impl netbench::Trace,
            config: Option<multiplex::Config>,
            (rx_buffer, tx_buffer): (usize, usize),
        ) -> Result<()> {
            let connection = tokio::io::BufStream::with_capacity(rx_buffer, tx_buffer, connection);

            let mut timer = netbench::timer::Tokio::default();
            let before = timer.now();

            let connection = tokio_boring::accept(acceptor.deref(), connection).await?;

            let now = timer.now();
            trace.connect(now, conn_id, now - before);

            let mut connection = Box::pin(connection);

            let server_idx = connection.read_u64().await?;
            let scenario = scenario
                .connections
                .get(server_idx as usize)
                .ok_or("invalid connection id")?;

            let mut checkpoints = HashSet::new();

            if let Some(config) = config {
                let conn = netbench::multiplex::Connection::new(conn_id, connection, config);
                let conn = netbench::Driver::new(scenario, conn);
                conn.run(&mut trace, &mut checkpoints, &mut timer).await?;
            } else {
                let conn = netbench::duplex::Connection::new(conn_id, connection);
                let conn = netbench::Driver::new(scenario, conn);
                conn.run(&mut trace, &mut checkpoints, &mut timer).await?;
            }

            Ok(())
        }
    }

    async fn server(&self) -> Result<TcpListener> {
        let server = TcpListener::bind((self.opts.ip, self.opts.port)).await?;
        Ok(server)
    }

    fn ssl_acceptor(&self) -> Result<SslAcceptor> {
        let (_, private_key) = self.opts.certificate();
        let pkcs12 = Pkcs12::from_der(&private_key.pkcs12)?;
        let identity = pkcs12.parse("")?;

        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
        builder.set_private_key(&identity.pkey)?;
        builder.set_certificate(&identity.cert)?;
        if let Some(chain) = identity.chain {
            for ca in chain {
                builder.add_extra_chain_cert(ca)?;
            }
        }

        Ok(builder.build())
    }
}
