from PyQt6.QtWebEngineWidgets import QWebEngineView

from PyQt6.QtCore import QUrl


class MapWidget(QWebEngineView):

    def __init__(self):

        super().__init__()

        self.map_ready = False

        self.loadFinished.connect(
            self.on_load_finished
        )

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
                    'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
                    {
                        attribution: 'OpenStreetMap'
                    }
                ).addTo(map);

                function addMarker(
                    lat,
                    lon,
                    text
                ) {

                    L.circleMarker(
                        [lat, lon],
                        {
                            radius: 8,
                            color: 'red'
                        }
                    )
                    .addTo(map)
                    .bindPopup(text);
                }

            </script>

        </body>
        </html>
        """

        self.setHtml(html, QUrl(""))

    def on_load_finished(self):

        self.map_ready = True