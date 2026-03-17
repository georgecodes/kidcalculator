const target = document.querySelector('textarea.target');
const kid = document.querySelector('input.kid');
const copyBtn = document.getElementById('copyBtn');
const toast = document.getElementById('toast');
const details = document.getElementById('details');
const detailGrid = document.getElementById('detailGrid');

target.addEventListener('paste', (event) => {
    let pem = (event.clipboardData || window.clipboardData).getData('text');

    const selection = window.getSelection();
    if (!selection.rangeCount) return false;

    // Compute kid
    const der = forge.pki.pemToDer(pem);
    const sh = forge.md.sha256.create();
    sh.update(der.getBytes());
    const d = sh.digest();
    kid.value = btoa(d.getBytes()).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');

    // Parse and display cert details
    try {
        const cert = forge.pki.certificateFromPem(pem);
        renderDetails(cert, der);
    } catch (e) {
        details.classList.remove('show');
    }
});

function fingerprint(der, algorithm) {
    const md = forge.md[algorithm].create();
    md.update(der.getBytes());
    return md.digest().toHex().match(/.{2}/g).join(':').toUpperCase();
}

function getAttr(dn, shortName) {
    const attr = dn.getField(shortName);
    return attr ? attr.value : '—';
}

function formatDN(dn) {
    return dn.attributes.map(a => `${a.shortName}=${a.value}`).join(', ') || '—';
}

function formatDate(date) {
    return date.toISOString().replace('T', ' ').replace('.000Z', ' UTC');
}

function expiryClass(notAfter) {
    const now = new Date();
    const diff = notAfter - now;
    const days = diff / (1000 * 60 * 60 * 24);
    if (diff < 0) return 'expired';
    if (days < 30) return 'expiring-soon';
    return 'valid';
}

function getSANs(cert) {
    const ext = cert.getExtension('subjectAltName');
    if (!ext) return '—';
    return ext.altNames.map(n => {
        if (n.type === 2) return n.value;          // DNS
        if (n.type === 7) return n.ip;             // IP
        if (n.type === 1) return `email:${n.value}`; // email
        return n.value;
    }).join(', ');
}

function getKeyUsage(cert) {
    const ku = cert.getExtension('keyUsage');
    if (!ku) return '—';
    const flags = ['digitalSignature','nonRepudiation','keyEncipherment',
                   'dataEncipherment','keyAgreement','keyCertSign','cRLSign'];
    return flags.filter(f => ku[f]).join(', ') || '—';
}

function getEKU(cert) {
    const eku = cert.getExtension('extKeyUsage');
    if (!eku) return '—';
    const names = {
        serverAuth: 'TLS Server', clientAuth: 'TLS Client',
        codeSigning: 'Code Signing', emailProtection: 'Email',
        timeStamping: 'Time Stamping', OCSPSigning: 'OCSP Signing'
    };
    return Object.keys(names).filter(k => eku[k]).map(k => names[k]).join(', ') || '—';
}

function renderDetails(cert, der) {
    const bc = cert.getExtension('basicConstraints');
    const isCA = bc && bc.cA;
    const expClass = expiryClass(cert.validity.notAfter);

    const pubKey = cert.publicKey;
    let keyInfo = '—';
    if (pubKey.n) {
        keyInfo = `RSA ${pubKey.n.bitLength()} bit`;
    } else if (pubKey.curve) {
        keyInfo = `EC (${pubKey.curve})`;
    } else if (pubKey.edAlgorithm) {
        keyInfo = pubKey.edAlgorithm;
    }

    const rows = [
        { label: 'Subject', value: formatDN(cert.subject), full: true },
        { label: 'Issuer', value: formatDN(cert.issuer), full: true },
        { label: 'Serial', value: cert.serialNumber },
        { label: 'Type', value: `<span>${isCA ? 'CA Certificate' : 'End-Entity'}</span><span class="badge ${isCA ? 'ca' : 'end-entity'}">${isCA ? 'CA' : 'EE'}</span>` },
        { label: 'Not Before', value: formatDate(cert.validity.notBefore) },
        { label: 'Not After', value: formatDate(cert.validity.notAfter), cls: expClass },
        { label: 'Public Key', value: keyInfo },
        { label: 'Signature Algorithm', value: cert.siginfo.algorithmOid ? cert.signatureOid : (cert.siginfo.algorithmOid || cert.signatureOid) },
        { label: 'Subject Alt Names', value: getSANs(cert), full: true },
        { label: 'Key Usage', value: getKeyUsage(cert), full: true },
        { label: 'Extended Key Usage', value: getEKU(cert), full: true },
        { label: 'SHA-1 Fingerprint', value: fingerprint(der, 'sha1'), full: true },
        { label: 'SHA-256 Fingerprint', value: fingerprint(der, 'sha256'), full: true },
    ];

    detailGrid.innerHTML = rows.map(r => `
        <div class="detail-item ${r.full ? 'full' : ''} ${r.cls || ''}">
            <div class="detail-label">${r.label}</div>
            <div class="detail-value">${r.value}</div>
        </div>
    `).join('');

    details.classList.add('show');
}

function copyKid() {
    if (!kid.value) return;
    navigator.clipboard.writeText(kid.value);
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2000);
}

kid.addEventListener('click', copyKid);
copyBtn.addEventListener('click', copyKid);
