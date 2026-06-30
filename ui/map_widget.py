from PyQt6.QtWebEngineWidgets import QWebEngineView

from PyQt6.QtCore import QUrl


class MapWidget(QWebEngineView):

    def __init__(self):

        super().__init__()

        self.map_ready = False

        self.loadFinished.connect(self.on_load_finished)

                
        self.pending_paths = []
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
                    background: #1E293B;
                    border: 1px solid #334155;
                    border-radius: 12px;
                    box-shadow: 0 8px 20px rgba(0,0,0,0.45);
                    width: 180px
                }

                .leaflet-popup-content {
                    margin: 6px;
                    color: #F8FAFC;
                    font-family: "Segoe UI", sans-serif;
                    font-size: 12px;
                    line-height: 1;
                }

                .leaflet-popup-tip {
                    background: #1E293B;
                }

                .leaflet-container a {
                    color: #60A5FA;
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
                    originLat,
                    originLon,
                    destLat,
                    destLon,
                    popupText,
                    severity
                ){
                

                    var origin = [originLat, originLon];

                    var destination = [destLat, destLon];       

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
                    ).addTo(map);

                    marker.bindPopup(popupText, {
                        autoPan: false,
                        keepInView: false,
                        autoClose: false,
                        closeButton: true,
                        maxWidth: 260,
                        minWidth: 220
                    });

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

        self.setHtml(html)

    def on_load_finished(self, ok):

        print("Map ready:", ok)

        if not ok:
            return

        self.map_ready = True

        for (
            origin_lat,
            origin_lon,
            dest_lat,
            dest_lon,
            popup,
            severity
        ) in self.pending_paths:

            self.add_attack_path(
                origin_lat,
                origin_lon,
                dest_lat,
                dest_lon,
                popup,
                severity
            )

        self.pending_paths.clear()

    def add_attack_path(
        self,
        origin_lat,
        origin_lon,
        dest_lat,
        dest_lon,
        popup,
        severity
    ):
        
        
        
        if not self.map_ready:

            self.pending_paths.append(
                (
                    origin_lat,
                    origin_lon,
                    dest_lat,
                    dest_lon,
                    popup,
                    severity
                )
            )

            return


        popup = (
            popup
            .replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\n", "<br>")
        )

        self.page().runJavaScript(
            f"""
            addAttackPath(
                {origin_lat},
                {origin_lon},
                {dest_lat},
                {dest_lon},
                '{popup}',
                '{severity}'
            );
            """
        )
