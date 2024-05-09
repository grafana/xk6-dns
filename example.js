import dns from 'k6/x/dns';

export const options = {
    vus: 10,
    iterations: 200,
}

export default async function () {
    const resolveResults = await dns.resolve("k6.io", "A", {
        nameserver: "192.168.2.100:53"
    });
    // console.log(`resolved the k6.io domain using cloudflare dns servers to the following IPs: ${resolveResults}`);

    const lookupResults = await dns.lookup("k6.io");
    // console.log(`looking up the k6.io domain using system defined dns servers to the following IPs: ${resolveResults}`);
}
