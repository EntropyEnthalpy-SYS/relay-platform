//! The agent's side of panel-managed reverse tunnels: the tunnel key, the
//! public end's tunnel listeners (in the engine, whose rules open paths
//! through them) and the private end's dials.
use crate::{
    reverse_mux::managed::{self, Client, Identity, Server},
    reverse_tunnel::{Desired, Report, Role, TunnelReport},
    store::Store,
};
use anyhow::Result;
use std::sync::Arc;

/// Agent metadata key of the tunnel key. It never leaves the agent; only
/// its certificate's fingerprint is reported.
const KEY: &str = "agent_reverse_tunnel_key";
/// Agent metadata key of the tunnels last received, run again after a
/// restart while the controller is unreachable.
const SAVED: &str = "agent_reverse_tunnels";

pub(super) struct Tunnels {
    identity: Option<Identity>,
    server: Arc<Server>,
    client: Client,
    saved: String,
}

impl Tunnels {
    pub fn new(store: &Store, server: Arc<Server>) -> Result<Self> {
        let identity = store
            .metadata(KEY)?
            .map(|saved| Identity::from_saved(&saved))
            .transpose()?;
        let mut tunnels = Self {
            identity,
            server,
            client: Client::default(),
            saved: String::new(),
        };
        if let Some(saved) = store.metadata(SAVED)?
            && let Ok(desired) = serde_json::from_str::<Desired>(&saved)
        {
            tunnels.saved = saved;
            tunnels.apply(&desired);
        }
        Ok(tunnels)
    }

    fn apply(&self, desired: &Desired) {
        let listeners: Vec<managed::Listener> = desired
            .listeners
            .iter()
            .map(|listener| managed::Listener {
                listen: listener.listen,
                tunnels: listener
                    .tunnels
                    .iter()
                    .map(|t| managed::Admitted {
                        id: t.id.clone(),
                        token: t.token.clone(),
                    })
                    .collect(),
            })
            .collect();
        self.server.reconcile(self.identity.as_ref(), &listeners);
        let dials: Vec<managed::Dial> = desired
            .dials
            .iter()
            .map(|dial| managed::Dial {
                id: dial.id.clone(),
                server: dial.server.clone(),
                fingerprint: dial.fingerprint.clone(),
                token: dial.token.clone(),
                target: dial.target.clone(),
                tcp: dial.protocol.tcp(),
                udp: dial.protocol.udp(),
            })
            .collect();
        self.client.reconcile(&dials);
    }

    /// Runs what the controller sent; makes the key when this server is a
    /// public end and has none yet.
    pub fn reconcile(&mut self, store: &Store, desired: &Desired) -> Result<()> {
        if self.identity.is_none() && (desired.key || !desired.listeners.is_empty()) {
            let identity = Identity::generate()?;
            store.set_metadata(KEY, &identity.to_saved())?;
            tracing::info!(fingerprint = %identity.fingerprint(), "reverse tunnel key created");
            self.identity = Some(identity);
        }
        self.apply(desired);
        let saved = serde_json::to_string(desired)?;
        if saved != self.saved {
            store.set_metadata(SAVED, &saved)?;
            self.saved = saved;
        }
        Ok(())
    }

    pub fn report(&self) -> Report {
        let public = self.server.status().into_iter().map(|s| (s, Role::Public));
        let private = self.client.status().into_iter().map(|s| (s, Role::Private));
        Report {
            managed: true,
            fingerprint: self.identity.as_ref().map(Identity::fingerprint),
            tunnels: public
                .chain(private)
                .take(crate::reverse_tunnel::MAX_REPORTED)
                .map(|(status, role)| TunnelReport {
                    id: status.id,
                    role,
                    connected_secs: status.connected_for.map(|d| d.as_secs()),
                    error: status.error.map(|e| e.chars().take(512).collect()),
                })
                .collect(),
        }
    }
}
