from PyQt6.QtWebEngineWidgets import QWebEngineView

from PyQt6.QtCore import QUrl


class MapWidget(QWebEngineView):

    def __init__(self):

        super().__init__()

        self.map_ready = False

        self.loadFinished.connect(self.on_load_finished)

        html = """
        <!DOCTYPE html>
        <html>

        <head>

            <meta charset="utf-8"/>

            <title>Mycelium Threat Map</title>

            <link
                rel="stylesheet"
                href="https://unpkg.com/leaflet/dist/leaflet.css"
            />

            <script
                src="https://unpkg.com/leaflet/dist/leaflet.js">
            </script>

            <style>

                html, body {

                    margin: 0;
                    padding: 0;
                    height: 100%;
                    background: #111;
                }

                #map {

                    width: 100%;
                    height: 100%;

                }

                .leaflet-popup-content-wrapper {

    background: #0d1117;
    color: #00ffee;
    border: 1px solid #00ffee;
    border-radius: 10px;
    font-family: 'Share Tech Mono';
}

.leaflet-popup-tip {

    background: #0d1117;
}

.leaflet-popup-content {

    font-size: 12px;
}

            </style>

        </head>

        <body>

            <div id="map"></div>

            <script>

                var map = L.map('map').setView(
                    [20, 0],
                    2
                );

            L.tileLayer(
                'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
                {
                    attribution: '&copy; OpenStreetMap &copy; CARTO'
                }
                ).addTo(map);

                function addAttackPath(
                    lat,
                    lon,
                    popupText,
                    severity
                ) {

                    var origin = [51.5074, -0.1278];

                    var destination = [lat, lon];

                    let color = 'cyan';

                    if (severity === 'MEDIUM') {
                        color = 'yellow';
                    }

                    if (severity === 'HIGH') {
                        color = 'red';
                    }

                    var line = L.polyline(
                        [origin, destination],
                        {
                            color: color,
                            weight: 3,
                            opacity: 0.8
                        }
                    ).addTo(map);

                    var marker = L.circleMarker(
                        destination,
                        {
                            radius: 6,
                            color: color,
                            fillColor: color,
                            fillOpacity: 0.8
                        }
                    )
                    .addTo(map)
                    .bindPopup(popupText);

                    let opacity = 0.8;

                    let fade = setInterval(function() {

                        opacity -= 0.02;

                        line.setStyle({
                            opacity: opacity
                        });

                        marker.setStyle({
                            opacity: opacity,
                            fillOpacity: opacity
                        });

                        if (opacity <= 0) {

                            map.removeLayer(line);

                            map.removeLayer(marker);

                            clearInterval(fade);
                        }

                    }, 200);
                }

            </script>

        </body>
        </html>
        """

        self.setHtml(html, QUrl(""))

    def on_load_finished(self):

        self.map_ready = True
