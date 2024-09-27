import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import requests
import threading
import os

# Fonction pour sélectionner les fichiers
def select_files():
    new_file_paths = filedialog.askopenfilenames()
    current_files = file_entry.get("1.0", tk.END).strip().split('\n')
    all_files = list(filter(None, current_files))
    all_files.extend(new_file_paths)
    file_entry.delete("1.0", tk.END)
    file_entry.insert("1.0", '\n'.join(all_files))

# Récupérer les résultats d'analyse
def get_analysis_results(api_key, resource):
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                            params={'apikey': api_key, 'resource': resource})
    return response.json()

# Créer un cadre pour les résultats
def create_result_frame(parent, engine, detected, version):
    frame = ttk.Frame(parent, padding="5", style="Results.TFrame")
    frame.pack(fill='x', padx=5, pady=2)

    engine_label = ttk.Label(frame, text=engine, font=('Arial', 12, 'bold'))
    engine_label.pack(side='left', padx=5)

    result_label = ttk.Label(frame, text="Détecté" if detected else "Non détecté", 
                              foreground="red" if detected else "green")
    result_label.pack(side='left', padx=5)

    version_label = ttk.Label(frame, text=f"Version: {version}", font=('Arial', 10))
    version_label.pack(side='right', padx=5)

# Vérifier un fichier
def check_file(api_key, file_path, index, total_files, summary):
    try:
        with open(file_path.strip(), 'rb') as file:
            files = {'file': file}
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan',
                                     files=files,
                                     params={'apikey': api_key})
            json_response = response.json()

        if response.status_code == 200 and 'resource' in json_response:
            resource_id = json_response['resource']
            app.after(15000, lambda: get_results(api_key, resource_id, file_path.strip(), index, total_files, summary))
        else:
            messagebox.showerror("Erreur", f"Analyse de {file_path.strip()} : Échec - {json_response.get('verbose_msg', 'Erreur inconnue')}")
    except Exception as e:
        messagebox.showerror("Erreur", f"Analyse de {file_path.strip()} : Erreur - {str(e)}")
    finally:
        progress['value'] = ((index + 1) / total_files) * 100
        app.update()

# Obtenir les résultats d'analyse
def get_results(api_key, resource_id, file_path, index, total_files, summary):
    results = get_analysis_results(api_key, resource_id)

    result_window = tk.Toplevel(app)
    result_window.title("Résultats d'analyse")
    result_window.geometry("600x400")
    
    result_window.configure(bg="black")

    tk.Label(result_window, text=f"Résultats pour {file_path} :", font=('Arial', 14, 'bold'), bg="black", fg="white").pack(pady=5)
    
    if results['response_code'] == 1:
        if 'scans' in results:
            for engine, data in results['scans'].items():
                detected = data['detected']
                create_result_frame(result_window, engine, detected, data.get('version', 'Inconnu'))
                if detected:
                    summary['malicious'] = True

        ttk.Separator(result_window, orient='horizontal').pack(fill='x', pady=5)

        if index < total_files - 1:
            next_file_path = file_entry.get("1.0", tk.END).strip().split('\n')[index + 1]
            threading.Thread(target=check_file, args=(api_key, next_file_path.strip(), index + 1, total_files, summary)).start()
        else:
            if summary['malicious']:
                messagebox.showinfo("Terminé", "Analyse terminée. Des fichiers malveillants ont été détectés.")
            else:
                messagebox.showinfo("Terminé", "Analyse terminée. Aucun fichier malveillant détecté.")
    else:
        messagebox.showerror("Erreur", f"Résultat introuvable pour {file_path}.")

# Vérifier les fichiers
def check_files():
    api_key = api_key_entry.get()
    file_paths = file_entry.get("1.0", tk.END).strip().split('\n')
    if not file_paths or not api_key:
        messagebox.showerror("Erreur", "Veuillez entrer votre clé API et sélectionner des fichiers.")
        return

    total_files = len(file_paths)
    first_file_path = file_paths[0].strip()
    summary = {'malicious': False}
    threading.Thread(target=check_file, args=(api_key, first_file_path, 0, total_files, summary)).start()

# Changer le thème
def set_theme(theme):
    color_map = {
        "Naruto": "orange",
        "Anarchiste": "black",
        "Communiste": "red",
        "Pokémon": "lightgreen",
        "VirusTotal": "blue",
        "Manga": "pink",
    }
    text_color_map = {
        "Anarchiste": "white",
        "default": "black"
    }
    bg_color = color_map.get(theme, "white")
    text_color = text_color_map.get(theme, "black")
    app.configure(bg=bg_color)
    for widget in app.winfo_children():
        if isinstance(widget, ttk.Widget):
            widget.configure(style="TLabel")
        else:
            widget.configure(bg=bg_color, fg=text_color)

# Interface principale
app = tk.Tk()
app.title("cKEKSAFE")
app.geometry("600x400")



style = ttk.Style()
style.configure("Results.TFrame", background="lightgray")
style.configure("TLabel", background="white", font=('Arial', 10))

# Champs et boutons
tk.Label(app, text="Entrez votre clé API :").pack(pady=10)
api_key_entry = tk.Entry(app, width=50, show="*")
api_key_entry.pack(pady=5)

tk.Label(app, text="Sélectionnez des fichiers :").pack(pady=10)
file_entry = tk.Text(app, width=50, height=10)
file_entry.pack(pady=5)

select_button = tk.Button(app, text="Parcourir", command=select_files)
select_button.pack(pady=5)

check_button = tk.Button(app, text="Vérifier", command=check_files)
check_button.pack(pady=10)

theme_var = tk.StringVar(value="Choisir un thème")
theme_menu = ttk.OptionMenu(app, theme_var, "Choisir un thème", "Naruto", "Anarchiste", "Communiste", "Pokémon", "VirusTotal", "Manga", command=set_theme)
theme_menu.pack(pady=10)

progress = ttk.Progressbar(app, orient='horizontal', length=300, mode='determinate')
progress.pack(pady=10)

app.mainloop()
