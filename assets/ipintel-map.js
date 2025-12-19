document.addEventListener('DOMContentLoaded', () => {
    if (typeof deck === 'undefined') {
        console.error("Deck.gl not loaded");
        return;
    }

    const worldUrl = IPIntelMapData.worldUrl;
    const ajaxUrl  = IPIntelMapData.ajaxUrl;

    Promise.all([
        fetch(worldUrl).then(r => r.json()),
        fetch(ajaxUrl + '?action=ipintel_map_points').then(r => r.json())
    ]).then(([world, points]) => {

        const threatLayer = new deck.ScatterplotLayer({
            id: 'ipintel-threat-points',
            data: points,
            pickable: false,
            opacity: 0.9,

            radiusMinPixels: 4,
            radiusMaxPixels: 26,

            getPosition: d => [d.lon, d.lat],

            getRadius: d => {
                if (d.blacklisted || d.decision === 'block') return 90000;
                if (d.decision === 'challenge') return 60000;
                return 35000;
            },

            getFillColor: d => {

                // 🔴 BLOCK / BLACKLIST
                if (d.blacklisted || d.decision === 'block') {
                    return [255, 60, 60]; // red
                }

                // 🟡 CHALLENGE (not passed)
                if (d.decision === 'challenge' && !d.challenge_passed) {
                    return [255, 200, 0]; // yellow
                }

                // 🟢 NEON SAFE (allow / whitelist / passed)
                return [0, 255, 220]; // neon cyan
            }
        });

        new deck.DeckGL({
            container: 'ipintel-map',
            mapStyle: null,
            initialViewState: {
                longitude: 0,
                latitude: 20,
                zoom: 0.4,
                minZoom: 0.4,
                maxZoom: 12
            },
            controller: false,
            layers: [
                new deck.GeoJsonLayer({
                    id: 'world-outline',
                    data: world,
                    stroked: true,
                    filled: false,
                    pickable: false,
                    getLineColor: [0, 200, 255, 255],
                    getLineWidth: 1,
                    lineWidthMinPixels: 1.2
                }),
                threatLayer
            ]
        });

    }).catch(err => {
        console.error("Map load error:", err);
    });
});

