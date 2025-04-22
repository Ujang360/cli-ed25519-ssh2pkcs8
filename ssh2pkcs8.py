#!/usr/bin/env python3

import click
import datetime as dt
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


@click.command()
@click.argument("input_key", type=click.Path(exists=True))
@click.option("--common-name", "-cn", required=True, help="Common Name")
@click.option("--dc", multiple=True, help="Domain Component(s)")
@click.option(
    "--san",
    multiple=True,
    help="Subject Alternative Names (DNS)",
)
@click.option(
    "--validity-days",
    default=3650,
    show_default=True,
    help="Certificate validity period in days",
)
@click.option("--key-out", type=click.Path(), help="Output file for PKCS#8 private key")
@click.option("--cert-out", type=click.Path(), help="Output file for X.509 certificate")
def convert_and_generate_cert(
    input_key, common_name, dc, san, validity_days, key_out, cert_out
):
    """
    Convert OpenSSH Ed25519 PRIVATE KEY to PKCS#8 and generate a self-signed X.509 certificate.
    """

    # Load OpenSSH private key
    with open(input_key, "rb") as f:
        openssh_data = f.read()

    private_key = serialization.load_ssh_private_key(
        openssh_data, password=None, backend=default_backend()
    )

    public_key = private_key.public_key()

    # Build subject/issuer name
    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    name_attrs += [x509.NameAttribute(NameOID.DOMAIN_COMPONENT, d) for d in dc]
    subject = issuer = x509.Name(name_attrs)

    # Start building certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(dt.UTC))
        .not_valid_after(datetime.now(dt.UTC) + timedelta(days=validity_days))
    )

    # Add SAN extension if provided
    if san:
        san_list = [x509.DNSName(host) for host in san]
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )

    # Sign the certificate
    cert = cert_builder.sign(private_key, algorithm=None, backend=default_backend())

    # Write outputs
    key_output = key_out or f"{input_key}_pkcs8.pem"
    cert_output = cert_out or f"{input_key}_cert.pem"

    with open(key_output, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(cert_output, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    click.echo(f"✅ PKCS#8 private key saved to: {key_output}")
    click.echo(f"✅ X.509 certificate saved to: {cert_output}")


if __name__ == "__main__":
    convert_and_generate_cert()
