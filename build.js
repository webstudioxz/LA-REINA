import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🔨 Construyendo proyecto para producción...');

if (!fs.existsSync('dist')) {
    fs.mkdirSync('dist');
}

const filesToCopy = [
    'index.html', 
    'admin.html', 
    'server.js', 
    'package.json',
    'style.css',
    'app.js',
    '404.html'
];

filesToCopy.forEach(file => {
    if (fs.existsSync(file)) {
        fs.copyFileSync(file, `dist/${file}`);
        console.log(`✅ Copiado: ${file}`);
    } else {
        console.log(`⚠️ No encontrado: ${file}`);
    }
});

console.log('✅ Build completado!');