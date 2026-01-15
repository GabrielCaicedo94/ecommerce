const bcrypt = require('bcryptjs');

// Define tu NUEVA CLAVE aquí
const NEW_PASSWORD = 'Admin%123'; 

async function generateHash() {
    console.log(`Clave original: ${NEW_PASSWORD}`);
    
    // Genera un nuevo hash con 10 rondas de complejidad
    const newHash = await bcrypt.hash(NEW_PASSWORD, 10);
    
    console.log("--------------------------------------------------");
    console.log("HASH GENERADO:");
    console.log(newHash); // VALOR QUE NECESITAS COPIAR
    console.log("--------------------------------------------------");
}

generateHash();

// En tu terminal, estando en la carpeta backend, ejecuta el script: node generate_hash.js (para nuevo Hash)