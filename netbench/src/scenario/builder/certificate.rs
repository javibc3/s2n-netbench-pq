// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, process::Command, sync::Arc};

use crate::scenario;
use openssl::x509::X509Req;
use openssl::x509::X509;
use openssl::pkey::PKey;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use openssl::asn1::Asn1Time;

#[derive(Clone, Debug, Hash)]
pub(crate) enum Certificate {
    Authority {
        alg: String,
    },
    PrivateKey {
        alg: String,
        authority: u64,
        intermediates: Vec<String>,
    },
    Public,
}

fn create_ca(domain: &str, name: &String, alg: &String) -> (String, String) {
    let config = format!(
        r#"[ req ]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca

[ dn ]
C = US
CN = {name}

[ v3_ca ]
keyUsage = critical,keyCertSign,cRLSign
basicConstraints = critical,CA:true
subjectAltName = DNS:{domain}
"#
    );

    let config_path = format!("/tmp/{name}_ca.cnf");
    std::fs::write(&config_path, config).expect("Failed to write OpenSSL config");

    let output = Command::new("openssl")
        .args([
            "req",
            "-noenc",
            "-new",
            "-x509",
            "-days",
            "365",
            "-newkey",
            alg,
            "-keyout",
            "/tmp/ca_key.pem",
            "-out",
            "/tmp/ca_cert.pem",
            "-config",
            &config_path,
        ])
        .output()
        .expect("Failed to execute OpenSSL");

    if !output.status.success() {
        panic!(
            "OpenSSL failed with error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let cert = std::fs::read_to_string("/tmp/ca_cert.pem").expect("Failed to read CA certificate");
    let private_key = std::fs::read_to_string("/tmp/ca_key.pem").expect("Failed to read private key");

    (cert, private_key)
}

fn create_cert(
    domain: &str,
    name: &String,
    alg: &str,
    ca_cert: &String,
    ca_key: &String,
) -> (String, String) {
    let config = format!(
        r#"[ req ]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[ dn ]
C = US
CN = {name}

[ v3_req ]
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = {domain}
DNS.2 = *.{domain}
"#
    );

    let config_path = format!("/tmp/{name}_cert.cnf");
    std::fs::write(&config_path, config).expect("Failed to write OpenSSL config");

    let output = Command::new("openssl")
        .args([
            "req",
            "-noenc",
            "-new",
            "-newkey",
            alg,
            "-keyout",
            "/tmp/leaf_key.pem",
            "-out",
            "/tmp/leaf_csr.pem",
            "-config",
            &config_path,
        ])
        .output()
        .expect("Failed to execute OpenSSL");

    if !output.status.success() {
        panic!(
            "OpenSSL failed with error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let csr = X509Req::from_pem(&std::fs::read("/tmp/leaf_csr.pem").expect("Failed to read CSR")).expect("Failed to parse CSR");
    let ca_cert = X509::from_pem(ca_cert.as_bytes()).expect("Failed to parse CA certificate");
    let ca_key = PKey::private_key_from_pem(ca_key.as_bytes()).expect("Failed to parse CA private key");

    let mut builder = X509::builder().expect("Failed to create X509 builder");
    builder.set_version(2).expect("Failed to set version");
    builder.set_subject_name(csr.subject_name()).expect("Failed to set subject name");
    builder.set_issuer_name(ca_cert.subject_name()).expect("Failed to set issuer name");
    builder.set_pubkey(&csr.public_key().expect("Failed to get public key")).expect("Failed to set public key");
    builder.set_not_before(&Asn1Time::days_from_now(0).expect("Failed to set not before")).expect("Failed to set not before");
    builder.set_not_after(&Asn1Time::days_from_now(365).expect("Failed to set not after")).expect("Failed to set not after");

    let basic_constraints = BasicConstraints::new().critical().ca().build().expect("Failed to build BasicConstraints");
    builder.append_extension(basic_constraints).expect("Failed to append BasicConstraints");

    let key_usage = KeyUsage::new().critical().digital_signature().key_encipherment().build().expect("Failed to build KeyUsage");
    builder.append_extension(key_usage).expect("Failed to append KeyUsage");

    let san = SubjectAlternativeName::new()
        .dns(domain)
        .dns(&format!("*.{}", domain))
        .build(&builder.x509v3_context(Some(&ca_cert), None))
        .expect("Failed to build SubjectAlternativeName");
    builder.append_extension(san).expect("Failed to append SubjectAlternativeName");

    let message_digest = match alg {
        "rsa:2048" | "rsa:4096" => openssl::hash::MessageDigest::sha256(),
        _ => openssl::hash::MessageDigest::null(),
    };
    builder.sign(&ca_key, message_digest).expect("Failed to sign certificate");

    let cert = builder.build();
    std::fs::write("/tmp/leaf_cert.pem", cert.to_pem().expect("Failed to write certificate")).expect("Failed to write certificate");

    let cert =
        std::fs::read_to_string("/tmp/leaf_cert.pem").expect("Failed to read leaf certificate");
    let private_key =
        std::fs::read_to_string("/tmp/leaf_key.pem").expect("Failed to read private key");

    (cert, private_key)
}

impl Certificate {
    pub(crate) fn build_all(
        certs: Vec<Self>,
        id: &scenario::Id,
    ) -> Vec<Arc<scenario::Certificate>> {
        let mut cas = HashMap::new();
        let mut ias = HashMap::new();
        let mut out = vec![];

        let domain = format!("{id}.net");
        for (cert_idx, cert) in certs.into_iter().enumerate() {
            match cert {
                Self::Authority { alg } => {
                    // Crear CA usando openssl
                    let name = format!("netbench CA {cert_idx}");
                    let (cert,key) = create_ca(&domain, &name, &alg);

                    out.push(Arc::new(scenario::Certificate {
                        pem: cert.clone(),
                        pkcs12: vec![],
                    }));

                    cas.insert(cert_idx as u64, (cert, key));
                }
                Self::PrivateKey {
                    alg,
                    authority,
                    intermediates,
                } => {
                    // Crear cualquier intermediario necesario
                    for (idx, alg) in intermediates.iter().enumerate() {
                        ias.entry((authority, idx, alg.clone()))
                            .or_insert_with(|| {
                                let name = format!("netbench IA {authority} {idx}");
                                create_ca(&domain, &name, alg)
                            });
                    }

                    // Cadena de autoridades que deben firmar este certificado
                    let (ca_cert,ca_key) = cas.get(&authority).unwrap();

                    // Crear el certificado final
                    let name = format!("netbench Leaf {cert_idx}");
                    let (chain, private_key) = create_cert(&domain, &name, &alg, &ca_cert, &ca_key);

                    // Serializar la clave privada y construir PKCS#12
                    let pkcs12 = {
                        let public = openssl::x509::X509::from_pem(chain.as_bytes()).unwrap();
                        let key =
                            openssl::pkey::PKey::private_key_from_pem(private_key.as_bytes())
                                .unwrap();
                        openssl::pkcs12::Pkcs12::builder()
                            .pkey(&key)
                            .cert(&public)
                            .build2("")
                            .unwrap()
                            .to_der()
                            .unwrap()
                    };

                    out.push(Arc::new(scenario::Certificate {
                        pem: private_key,
                        pkcs12,
                    }));
                    out.push(Arc::new(scenario::Certificate {
                        pem: chain,
                        pkcs12: vec![],
                    }));
                }
                Self::Public => {
                    // Public se maneja en PrivateKey
                }
            }
        }
        out
    }
}

#[derive(Clone, Debug)]
pub struct Authority {
    id: u64,
    state: super::State,
}

impl Authority {
    pub(crate) fn new<F: FnOnce(&mut AuthorityBuilder)>(state: super::State, f: F) -> Self {
        let default_alg = std::env::var("SIGNATURE_ALGORITHM").unwrap_or_else(|_| "rsa:2048".to_string());
        let mut builder = AuthorityBuilder { alg: default_alg };
        f(&mut builder);

        let id = state
            .certificates
            .push(Certificate::Authority { alg: builder.alg.clone() }) as u64;

        Self { id, state }
    }

    pub fn key_pair(&self) -> KeyPair {
        self.key_pair_with(|_| {})
    }

    pub fn key_pair_with<F: FnOnce(&mut KeyPairBuilder)>(&self, f: F) -> KeyPair {
        let default_alg = std::env::var("SIGNATURE_ALGORITHM").unwrap_or_else(|_| "rsa:2048".to_string());
        let mut builder = KeyPairBuilder {
            authority: self.id,
            intermediates: vec![],
            alg: default_alg,
        };

        f(&mut builder);

        let KeyPairBuilder {
            authority,
            intermediates,
            alg,
        } = builder;

        let private_key = self.state.certificates.push(Certificate::PrivateKey {
            alg,
            authority,
            intermediates,
        }) as u64;
        let certificate = self.state.certificates.push(Certificate::Public) as u64;

        KeyPair {
            private_key,
            certificate,
            authority,
        }
    }
}

#[derive(Debug)]
pub struct AuthorityBuilder {
    alg: String,
}

macro_rules! authority {
    ($(($alg:expr, $lower:ident)),* $(,)?) => {
        impl AuthorityBuilder {
            $(
                pub fn $lower(&mut self) -> &mut Self {
                    self.alg = $alg.to_string();
                    self
                }
            )*
        }
    };
}

authority!(
    ("rsa:2048", rsa_2048),
    ("rsa:4096", rsa_4096),
    ("ec:prime256v1", ecdsa),
    ("ed25519", ed25519),
);

#[derive(Copy, Clone, Debug)]
pub struct KeyPair {
    pub(crate) authority: u64,
    pub(crate) private_key: u64,
    pub(crate) certificate: u64,
}

#[derive(Debug)]
pub struct KeyPairBuilder {
    authority: u64,
    intermediates: Vec<String>,
    alg: String,
}

impl KeyPairBuilder {
    pub fn push_ia(&mut self) -> &mut Self {
        self.push_ia_with(|_| {})
    }

    pub fn push_ia_with<F: FnOnce(&mut AuthorityBuilder)>(&mut self, f: F) -> &mut Self {
        let default_alg = std::env::var("SIGNATURE_ALGORITHM").unwrap_or_else(|_| "rsa:2048".to_string());
        let mut builder = AuthorityBuilder { alg: default_alg };
        f(&mut builder);
        self.intermediates.push(builder.alg.clone());
        self
    }
}
