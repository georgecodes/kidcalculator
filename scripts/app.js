const target = document.querySelector('textarea.target');
const kid = document.querySelector('input.kid');
const copyBtn = document.getElementById('copyBtn');
const toast = document.getElementById('toast');

target.addEventListener('paste', (event) => {
    let pem = (event.clipboardData || window.clipboardData).getData('text');

    const selection = window.getSelection();
    if (!selection.rangeCount) return false;

    var der = forge.pki.pemToDer(pem);
    let sh = forge.md.sha256.create();
    sh.update(der.getBytes());
    let d = sh.digest();

    kid.value = btoa(d.getBytes()).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
});

function copyKid() {
    if (!kid.value) return;
    navigator.clipboard.writeText(kid.value);
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2000);
}

kid.addEventListener('click', copyKid);
copyBtn.addEventListener('click', copyKid);
