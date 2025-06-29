from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/alerts', methods=['GET'])
def get_alerts():
    return jsonify({
        "alerts": [
            {"id": 1, "type": "Critical", "message": "CPU usage high"},
            {"id": 2, "type": "Warning", "message": "Disk space low"}
        ]
    })

if __name__ == '__main__':
    app.run(debug=True)