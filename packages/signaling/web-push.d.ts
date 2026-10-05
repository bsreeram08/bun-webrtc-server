// ponytail: only the two web-push calls this service makes; add @types/web-push if more are needed.
declare module 'web-push' {
    const webpush: {
        generateVAPIDKeys(): { publicKey: string; privateKey: string };
        sendNotification(subscription: { endpoint: string; keys: { p256dh: string; auth: string } }, payload: string, options: {
            TTL: number; urgency: 'very-low' | 'low' | 'normal' | 'high'; topic?: string; vapidDetails: { subject: string; publicKey: string; privateKey: string };
        }): Promise<{ statusCode: number }>;
    };
    export default webpush;
}
