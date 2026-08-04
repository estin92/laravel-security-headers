import { createApp } from 'vue';
import App from './App.vue';
import './app.css';

const mount = document.getElementById('security-headers-viewer');

if (mount) {
    createApp(App).mount(mount);
}
