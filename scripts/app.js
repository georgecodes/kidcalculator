const target = document.querySelector('textarea.target');
const kid = document.querySelector('input.kid');



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

kid.addEventListener('click', (event) => {
    kid.select();
    kid.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(kid.value);
    
});
