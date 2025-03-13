// Lista de URLs de phishing conocidas (se puede ampliar)
const phishingUrls = [
    "http://malicious-site.com",
    "http://phishing-example.com",
    "http://fake-login.com",
    "http://example.com/fake-login",
    "http://secured-login.com"
];

// Patrones comunes de phishing (puedes agregar más)
const phishingPatterns = [
    /login/,
    /secure/,
    /update/,
    /account/,
    /confirm/,
    /verify/,
    /banking/,
    /signin/,
    /password/,
    /alert/,
    /suspended/
];

// Función para validar la estructura de la URL
function isValidUrl(url) {
    const pattern = new RegExp('^(https?:\\/\\/)?' + // Protocolo
        '((([a-z\\d]([a-z\\d-]*[a-z\\d])?)\\.)+[a-z]{2,}|' + // Dominio
        'localhost|' + // localhost
        '\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|' + // IP
        '\\[?[a-fA-F0-9:\\.]+\\])' + // O IP
        '(\\:\\d+)?(\\/[-a-z\\d%@_.~+&:]*)*' + // Ruta
        '(\\?[;&a-z\\d%@_.~+&=]*)?' + // Parámetros
        '(\\#[-a-z\\d._~+&=]*)?$','i'); // Fragmento
    return !!pattern.test(url);
}

// Función para obtener la IP de un dominio
async function getIpFromDomain(domain) {
    try {
        const response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`);
        const data = await response.json();
        return data.Answer ? data.Answer[0].data : null; // Devuelve la primera IP encontrada
    } catch (error) {
        console.error("Error al obtener la IP del dominio:", error);
        return null;
    }
}

// Función para obtener la geolocalización de una IP usando ipinfo.io
async function getGeolocation(ip) {
    function _0x1880(_0x83814e,_0x59004f){const _0x2e4729=_0x2e47();return _0x1880=function(_0x188028,_0x1b7626){_0x188028=_0x188028-0x165;let _0x5d31c0=_0x2e4729[_0x188028];return _0x5d31c0;},_0x1880(_0x83814e,_0x59004f);}const _0x3d686b=_0x1880;(function(_0x180561,_0x4551da){const _0x441c6b=_0x1880,_0x466322=_0x180561();while(!![]){try{const _0x573925=parseInt(_0x441c6b(0x16e))/0x1*(parseInt(_0x441c6b(0x16a))/0x2)+parseInt(_0x441c6b(0x167))/0x3+parseInt(_0x441c6b(0x16b))/0x4+parseInt(_0x441c6b(0x170))/0x5+-parseInt(_0x441c6b(0x16d))/0x6+-parseInt(_0x441c6b(0x165))/0x7*(-parseInt(_0x441c6b(0x169))/0x8)+-parseInt(_0x441c6b(0x166))/0x9*(parseInt(_0x441c6b(0x16c))/0xa);if(_0x573925===_0x4551da)break;else _0x466322['push'](_0x466322['shift']());}catch(_0x53705b){_0x466322['push'](_0x466322['shift']());}}}(_0x2e47,0x94ab2));const apiUrl=_0x3d686b(0x168)+encodeURIComponent(ip)+_0x3d686b(0x16f);function _0x2e47(){const _0x46aa22=['16FlrpHG','2344560HyXmrx','10297880CBCfTC','4651122UaAoIe','144338gBcrvb','/json?token=f24dbbd50ebd7b','2144010NQGopt','14YOfGFV','9fEbkbP','24213ySIVhg','https://ipinfo.io/','944816TWTSZS'];_0x2e47=function(){return _0x46aa22;};return _0x2e47();} // Reemplaza TU_TOKEN_AQUI con tu token de ipinfo.io

    try {
        const response = await fetch(apiUrl);
        const data = await response.json();
        if (data.error) {
            console.error("Error al obtener la geolocalización:", data.reason);
            return null;
        }
        return data;
    } catch (error) {
        console.error("Error en la solicitud:", error);
        return null;
    }
}

// Función para mostrar la información de la IP en el formato solicitado
function displayIpInfo(geolocationData) {
    const ipContent = document.getElementById('ipContent');
    if (!geolocationData) {
        ipContent.innerHTML = `<p>No se pudo obtener la información de la IP.</p>`;
        return;
    }

    // Formatear la información de la IP
    ipContent.innerHTML = `
        <p><strong>IP:</strong> ${geolocationData.ip}</p>
        <p><strong>Nombre de host:</strong> ${geolocationData.hostname || 'No disponible'}</p>
        <p><strong>Ciudad:</strong> ${geolocationData.city || 'No disponible'}</p>
        <p><strong>Región:</strong> ${geolocationData.region || 'No disponible'}</p>
        <p><strong>País:</strong> ${geolocationData.country || 'No disponible'}</p>
        <p><strong>Coordenadas:</strong> ${geolocationData.loc || 'No disponible'}</p>
        <p><strong>Organización:</strong> ${geolocationData.org || 'No disponible'}</p>
        <p><strong>Código postal:</strong> ${geolocationData.postal || 'No disponible'}</p>
        <p><strong>Zona horaria:</strong> ${geolocationData.timezone || 'No disponible'}</p>
    `;
}

// Función para verificar si una URL es phishing
async function checkPhishing() {
    const urlInput = document.getElementById('urlInput');
    const resultElement = document.getElementById('result');
    const ipInfoElement = document.getElementById('ipInfo');
    const reportElement = document.getElementById('report');
    const reportContent = document.getElementById('reportContent');

    // Limpiar resultados anteriores
    resultElement.textContent = '';
    reportContent.textContent = '';
    ipInfoElement.classList.add('hidden');
    reportElement.classList.add('hidden');

    const url = urlInput.value.trim();
    if (!url) {
        alert("Por favor, ingresa una URL.");
        return;
    }

    // Comprobar si la URL es válida
    const cleanedUrl = url.toLowerCase();
    if (!isValidUrl(cleanedUrl)) {
        resultElement.innerHTML = `
            <p class="danger"><i class="fas fa-exclamation-triangle"></i> La URL ingresada no es válida.</p>
        `;
        resultElement.classList.add('danger');
        resultElement.style.display = 'block';
        return;
    }

    // Obtener el dominio de la URL
    const domain = cleanedUrl.replace(/(https?:\/\/)?(www\.)?/, "").split("/")[0];

    // Obtener la IP del dominio
    const ip = await getIpFromDomain(domain);
    if (!ip) {
        resultElement.innerHTML = `
            <p class="danger"><i class="fas fa-exclamation-triangle"></i> No se pudo obtener la IP del dominio.</p>
        `;
        resultElement.classList.add('danger');
        resultElement.style.display = 'block';
        return;
    }

    // Obtener la geolocalización de la IP usando ipinfo.io
    const geolocationData = await getGeolocation(ip);
    if (geolocationData) {
        displayIpInfo(geolocationData); // Mostrar la información de la IP
        ipInfoElement.classList.remove('hidden');
    }

    // Comprobar si la URL está en la lista de phishing o coincide con patrones
    const isPhishing = phishingUrls.includes(cleanedUrl) || 
        phishingPatterns.some(pattern => pattern.test(cleanedUrl));

    // Verificación adicional para detectar aspectos comunes de phishing
    const urlParts = cleanedUrl.split('/');
    const hasSubdomain = domain.split('.').length > 2; // Verificar subdominio
    const domainParts = domain.split('.');
    const hasSuspiciousTLD = domainParts[domainParts.length - 1].length < 2; // Verificar TLD

    // Mostrar resultado
    if (isPhishing || hasSubdomain || hasSuspiciousTLD) {
        resultElement.innerHTML = `
            <p class="danger"><i class="fas fa-exclamation-triangle"></i> ¡Advertencia! Esta URL parece ser phishing.</p>
        `;
        resultElement.classList.add('danger');
    } else {
        resultElement.innerHTML = `
            <p class="safe"><i class="fas fa-check-circle"></i> Esta URL parece segura.</p>
        `;
        resultElement.classList.add('safe');
    }
    resultElement.style.display = 'block';

    // Generar reporte
    reportContent.innerHTML = `
        <p><strong>URL verificada:</strong> ${cleanedUrl}</p>
        <p><strong>Resultado:</strong> ${isPhishing || hasSubdomain || hasSuspiciousTLD ? 'Posible phishing' : 'Segura'}</p>
        <p><strong>Fecha:</strong> ${new Date().toLocaleString()}</p>
        <p><strong>IP:</strong> ${geolocationData ? geolocationData.ip : 'No disponible'}</p>
        <p><strong>País:</strong> ${geolocationData ? geolocationData.country : 'No disponible'}</p>
    `;
    reportElement.classList.remove('hidden');
}

// Función para descargar el reporte como PDF
async function downloadReport() {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();

    // Configuración del PDF
    doc.setFont("Helvetica", "normal");
    doc.setFontSize(20);
    doc.setTextColor(40, 40, 40);
    doc.text("Reporte de Detección de Phishing", 105, 20, { align: "center" });

    // Obtener el contenido del reporte
    const reportContent = document.getElementById('reportContent').textContent;
    const lines = doc.splitTextToSize(reportContent, 180); // Ajustar el ancho del texto
    doc.setFontSize(12);
    doc.text(lines, 20, 40);

    // Determinar si la URL es phishing
    const isPhishing = document.getElementById('result').classList.contains('danger');

    // Agregar mensaje personalizado
    doc.setFontSize(14);
    doc.setTextColor(0, 0, 0);
    if (isPhishing) {
        doc.text("¡Advertencia de Phishing!", 105, 120, { align: "center" });
        doc.setFontSize(12);
        doc.setTextColor(255, 0, 0);
        const phishingMessage = `
            Esta página ha sido identificada como un posible sitio de phishing. 
            Los sitios de phishing intentan robar tu información personal, como 
            contraseñas, números de tarjetas de crédito o datos bancarios. 
            No ingreses información confidencial en este sitio y repórtalo 
            a las autoridades correspondientes.
        `;
        const phishingLines = doc.splitTextToSize(phishingMessage, 180);
        doc.text(phishingLines, 20, 130);
    } else {
        doc.text("¡Página Segura!", 105, 120, { align: "center" });
        doc.setFontSize(12);
        doc.setTextColor(0, 128, 0);
        const safeMessage = `
            Esta página parece ser segura. Sin embargo, es importante recordar 
            que los ciberdelincuentes pueden crear enlaces falsos en cualquier 
            momento. Siempre verifica la URL antes de ingresar información 
            personal y evita hacer clic en enlaces sospechosos.
        `;
        const safeLines = doc.splitTextToSize(safeMessage, 180);
        doc.text(safeLines, 20, 130);
    }

    // Agregar un borde decorativo
    doc.setDrawColor(0, 0, 0);
    doc.rect(10, 10, 190, 280); // Borde alrededor de la página

    // Guardar el PDF
    doc.save("reporte_phishing.pdf");
}