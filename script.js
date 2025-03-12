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

// Función para obtener la geolocalización de una IP
async function getGeolocation(ip) {
    const apiUrl = `https://ipapi.co/${encodeURIComponent(ip)}/json/`; // API de ipapi.co

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

// Función para verificar si una URL es phishing
async function checkPhishing() {
    const urlInput = document.getElementById('urlInput');
    const resultElement = document.getElementById('result');
    const ipInfoElement = document.getElementById('ipInfo');
    const ipContent = document.getElementById('ipContent');
    const reportElement = document.getElementById('report');
    const reportContent = document.getElementById('reportContent');

    // Verificar si los elementos del DOM existen
    if (!urlInput || !resultElement || !ipInfoElement || !ipContent || !reportElement || !reportContent) {
        console.error("Error: No se encontraron todos los elementos del DOM.");
        return;
    }

    // Limpiar resultados anteriores
    resultElement.textContent = '';
    ipContent.textContent = '';
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

    // Obtener la geolocalización de la IP
    const geolocationData = await getGeolocation(ip);
    if (geolocationData) {
        ipContent.innerHTML = `
            <p><strong>IP:</strong> ${geolocationData.ip}</p>
            <p><strong>Ciudad:</strong> ${geolocationData.city}</p>
            <p><strong>Región:</strong> ${geolocationData.region}</p>
            <p><strong>País:</strong> ${geolocationData.country_name}</p>
            <p><strong>Proveedor de Internet:</strong> ${geolocationData.org}</p>
        `;
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
        <p><strong>País:</strong> ${geolocationData ? geolocationData.country_name : 'No disponible'}</p>
    `;
    reportElement.classList.remove('hidden');
}

// Función para descargar el reporte como PDF
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