/**
 * Guard AI Informer AI Voice Synthesis Engine
 * Integrates with Web Speech API for English (en-IN) and Telugu (te-IN) alerts.
 */
const InformerVoice = {
    isSupported: 'speechSynthesis' in window,

    speakEnglish(text, rate = 0.95, pitch = 1.0) {
        if (!this.isSupported) {
            console.warn('[Informer Voice] Web Speech API not supported in this browser.');
            return;
        }
        window.speechSynthesis.cancel(); // Stop any pending speech
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.lang = 'en-IN';
        utterance.rate = rate;
        utterance.pitch = pitch;

        // Try to select an Indian English voice if available
        const voices = window.speechSynthesis.getVoices();
        const enInVoice = voices.find(v => v.lang.includes('en-IN') || v.name.includes('India'));
        if (enInVoice) utterance.voice = enInVoice;

        window.speechSynthesis.speak(utterance);
    },

    speakTelugu(text, rate = 0.9, pitch = 1.0) {
        if (!this.isSupported) {
            console.warn('[Informer Voice] Web Speech API not supported in this browser.');
            return;
        }
        window.speechSynthesis.cancel();
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.lang = 'te-IN';
        utterance.rate = rate;
        utterance.pitch = pitch;

        const voices = window.speechSynthesis.getVoices();
        const teVoice = voices.find(v => v.lang.includes('te') || v.name.includes('Telugu'));
        if (teVoice) utterance.voice = teVoice;

        window.speechSynthesis.speak(utterance);
    },

    stop() {
        if (this.isSupported) {
            window.speechSynthesis.cancel();
        }
    }
};

window.InformerVoice = InformerVoice;
