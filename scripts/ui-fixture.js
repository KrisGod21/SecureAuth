// Isolated browser QA: no persisted records, no real users, no storage key file.
import { randomBytes } from 'node:crypto';
import { createApp } from '../server/app.js';
const project=await createApp({storageKey:randomBytes(32).toString('hex'),dbPath:':memory:',origin:'http://localhost:3001',passwordGenerator:async()=>({password:'TestOnly123!AbCd',source:'csprng-only'})});
const server=project.app.listen(3001,'127.0.0.1',()=>console.log('Isolated synthetic browser QA: http://localhost:3001'));
process.on('SIGINT',()=>server.close(()=>{project.close();process.exit(0);}));
