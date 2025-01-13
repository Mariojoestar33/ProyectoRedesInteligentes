import pyshark
import matplotlib.pyplot as plt
from collections import Counter
import pandas as pd


def analyze_sip_traffic(file_name="RedesInteligentes.pcapng"):
    try:
        capture = pyshark.FileCapture(file_name, display_filter="sip")
    except Exception as e:
        print(f"Error al cargar el archivo: {e}")
        return


    message_types = []
    timestamps = []
    retransmissions = []
    latency_data = []


    sip_requests = {}


    for packet in capture:
        try:
            if 'sip' in packet:
                sip_layer = packet.sip
                if hasattr(sip_layer, 'Method'):
                    method = sip_layer.Method
                    message_types.append(method)


                    # Capturar retransmisiones si existe el campo
                    if hasattr(sip_layer, 'is_retransmission') and sip_layer.is_retransmission == '1':
                        retransmissions.append(method)


                    # Guardar timestamp para latencia si es un INVITE o 200 OK
                    if method in ['INVITE', '200']:  
                        call_id = sip_layer.get_field('call_id')
                        if call_id:
                            if method == 'INVITE':
                                sip_requests[call_id] = float(packet.sniff_time.timestamp())
                            elif method == '200' and call_id in sip_requests:
                                start_time = sip_requests.pop(call_id)
                                end_time = float(packet.sniff_time.timestamp())
                                latency_data.append(end_time - start_time)


                timestamps.append(float(packet.sniff_time.timestamp()))
        except AttributeError:
            pass


    capture.close()


    # Contar los tipos de mensajes
    message_count = Counter(message_types)
    retransmission_count = Counter(retransmissions)


    # Crear un DataFrame para el análisis temporal
    df = pd.DataFrame({'timestamp': timestamps})
    df['timestamp_rounded'] = pd.to_datetime(df['timestamp'], unit='s').dt.floor('T')
    traffic_per_minute = df['timestamp_rounded'].value_counts().sort_index()


    # Graficar los resultados
    plt.figure(figsize=(18, 10))


    # Gráfica 1: Tipos de mensajes SIP
    plt.subplot(2, 2, 1)
    plt.bar(message_count.keys(), message_count.values(), color='skyblue')
    plt.title('Distribución de mensajes SIP')
    plt.xlabel('Tipo de mensaje SIP')
    plt.ylabel('Cantidad')
    plt.xticks(rotation=45)


    # Gráfica 2: Distribución temporal de los paquetes
    plt.subplot(2, 2, 2)
    plt.hist(timestamps, bins=20, color='lightgreen', edgecolor='black')
    plt.title('Distribución temporal de los paquetes SIP')
    plt.xlabel('Timestamp')
    plt.ylabel('Número de paquetes')


    # Gráfica 3: Tráfico SIP por minuto
    plt.subplot(2, 2, 4)
    traffic_per_minute.plot(kind='line', color='blue', marker='o')
    plt.title('Tráfico SIP a lo largo del tiempo (por minuto)')
    plt.xlabel('Tiempo')
    plt.ylabel('Cantidad de mensajes')


    plt.tight_layout()
    plt.show()


    # Gráfica adicional: Distribución de latencia entre INVITE y 200 OK
    if latency_data:
        plt.figure(figsize=(8, 6))
        plt.hist(latency_data, bins=20, color='purple', edgecolor='black')
        plt.title('Distribución de latencia entre INVITE y 200 OK')
        plt.xlabel('Latencia (segundos)')
        plt.ylabel('Frecuencia')
        plt.show()


analyze_sip_traffic()