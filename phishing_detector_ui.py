import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import joblib
from analyze_the_characteristics import extract_url_features
import pandas as pd
import threading
import csv
import os
from datetime import datetime

class PhishingDetectorUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Website Detection System")
        self.root.geometry("900x700")
        
        # Load model
        try:
            self.model = joblib.load('phishing_detection_model.joblib')
            print("Model loaded successfully")
        except:
            print("Model loading failed")
            self.model = None

        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure root grid to expand
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)

        # Create tabs
        self.tab_control = ttk.Notebook(main_frame)
        self.tab_control.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Single URL tab
        self.single_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.single_tab, text="Single URL")
        
        # Batch URL tab
        self.batch_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.batch_tab, text="Batch Testing")
        
        # Configure Single URL Tab
        self.setup_single_url_tab()
        
        # Configure Batch URL Tab
        self.setup_batch_url_tab()
        
        # Progress bar (shared)
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(main_frame, length=880, mode='determinate', 
                                      variable=self.progress_var)
        self.progress.grid(row=2, column=0, columnspan=2, pady=5)

        # Status label (shared)
        self.status_label = ttk.Label(main_frame, text="Ready")
        self.status_label.grid(row=3, column=0, columnspan=2, sticky=(tk.W))

    def setup_single_url_tab(self):
        # URL input area
        url_frame = ttk.LabelFrame(self.single_tab, text="URL Input", padding="5")
        url_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        url_frame.columnconfigure(0, weight=1)
        
        self.url_entry = ttk.Entry(url_frame, width=80)
        self.url_entry.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        self.check_button = ttk.Button(url_frame, text="Detect", command=self.start_detection)
        self.check_button.grid(row=0, column=1, padx=5, pady=5)
        
        # Single URL progress bar
        progress_frame = ttk.Frame(url_frame)
        progress_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.single_progress_var = tk.DoubleVar()
        self.single_progress = ttk.Progressbar(
            progress_frame, 
            length=700, 
            mode='determinate',
            variable=self.single_progress_var
        )
        self.single_progress.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # Single URL progress status
        self.single_status_label = ttk.Label(progress_frame, text="Ready")
        self.single_status_label.grid(row=0, column=1, padx=5, pady=5)

        # Feature display area
        features_frame = ttk.LabelFrame(self.single_tab, text="URL Features", padding="5")
        features_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        features_frame.columnconfigure(0, weight=1)
        features_frame.rowconfigure(0, weight=1)
        
        self.features_text = scrolledtext.ScrolledText(features_frame, width=40, height=20)
        self.features_text.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Detection result area
        result_frame = ttk.LabelFrame(self.single_tab, text="Detection Result", padding="5")
        result_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, width=40, height=20)
        self.result_text.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))

    def setup_batch_url_tab(self):
        # Batch input area
        batch_frame = ttk.LabelFrame(self.batch_tab, text="Batch URL Input", padding="5")
        batch_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.batch_file_path = tk.StringVar()
        self.batch_file_entry = ttk.Entry(batch_frame, width=70, textvariable=self.batch_file_path)
        self.batch_file_entry.grid(row=0, column=0, padx=5, pady=5)
        
        self.browse_button = ttk.Button(batch_frame, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=0, column=1, padx=5, pady=5)
        
        self.batch_check_button = ttk.Button(batch_frame, text="Test Batch", command=self.start_batch_detection)
        self.batch_check_button.grid(row=0, column=2, padx=5, pady=5)
        
        # Example URLs
        example_frame = ttk.LabelFrame(batch_frame, text="Example URLs", padding="5")
        example_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        example_urls = [
            "https://www.google.com",
            "https://www.microsoft.com",
            "https://www.apple.com",
            "https://www.amazon.com",
            "https://www.facebook.com",
            "http://tiny-url.com/atwbv",
            "http://tinyurl.com/ovz5bmr",
            "http://tinyurl.com/qcdez65",
            "http://tinyurl.com/pexnwqp",
            "http://bit.do/UPenn-secure"
        ]
        
        self.test_urls_text = scrolledtext.ScrolledText(example_frame, width=80, height=10)
        self.test_urls_text.grid(row=0, column=0, padx=5, pady=5)
        self.test_urls_text.insert(tk.END, "\n".join(example_urls))
        
        # Add Quick Test button for example URLs
        self.quick_test_button = ttk.Button(example_frame, text="Quick Test Examples", command=self.test_example_urls)
        self.quick_test_button.grid(row=1, column=0, padx=5, pady=5)
        
        # Batch progress
        progress_frame = ttk.Frame(example_frame)
        progress_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        progress_frame.columnconfigure(0, weight=1)
        
        # Batch progress indicators
        self.batch_progress_var = tk.DoubleVar()
        self.batch_progress = ttk.Progressbar(
            progress_frame, 
            length=700, 
            mode='determinate',
            variable=self.batch_progress_var
        )
        self.batch_progress.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # Progress label
        self.batch_progress_label = ttk.Label(progress_frame, text="0/0 URLs processed")
        self.batch_progress_label.grid(row=0, column=1, padx=5, pady=5)
        
        # Batch results area
        results_frame = ttk.LabelFrame(self.batch_tab, text="Batch Results", padding="5")
        results_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Results table
        columns = ('url', 'prediction', 'confidence', 'features')
        self.results_table = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        # Set column headings
        self.results_table.heading('url', text='URL')
        self.results_table.heading('prediction', text='Prediction')
        self.results_table.heading('confidence', text='Confidence')
        self.results_table.heading('features', text='Key Features')
        
        # Set column widths
        self.results_table.column('url', width=350)
        self.results_table.column('prediction', width=120)
        self.results_table.column('confidence', width=100)
        self.results_table.column('features', width=250)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_table.yview)
        self.results_table.configure(yscroll=scrollbar.set)
        
        # Place the table and scrollbar
        self.results_table.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S, tk.E))
        
        # Bottom buttons frame
        buttons_frame = ttk.Frame(results_frame)
        buttons_frame.grid(row=1, column=0, padx=5, pady=5, sticky=(tk.E))
        
        # Results summary label
        self.results_summary = ttk.Label(buttons_frame, text="")
        self.results_summary.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W))
        
        # Add Export button
        self.export_button = ttk.Button(buttons_frame, text="Export Results", command=self.export_results)
        self.export_button.grid(row=0, column=1, padx=5, pady=5, sticky=(tk.E))

    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select a file",
            filetypes=(("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*"))
        )
        if filename:
            self.batch_file_path.set(filename)

    def update_status(self, message, progress=None):
        self.status_label.config(text=message)
        if progress is not None:
            self.progress_var.set(progress)
        self.root.update_idletasks()
    
    def update_single_progress(self, message, progress=None):
        """Update the single URL detection progress bar and status"""
        self.single_status_label.config(text=message)
        if progress is not None:
            self.single_progress_var.set(progress)
        
        # Also update the main status
        self.update_status(message, progress)
        
        # Force UI update
        self.root.update_idletasks()
    
    def update_batch_progress(self, current, total):
        """Update the batch-specific progress bar and label"""
        # Update progress bar
        progress_percentage = (current / total) * 100 if total > 0 else 0
        self.batch_progress_var.set(progress_percentage)
        
        # Update progress label
        self.batch_progress_label.config(text=f"{current}/{total} URLs processed")
        
        # Update main status too
        self.update_status(f"Processing batch: {current}/{total} URLs", progress_percentage)
        
        # Force UI update
        self.root.update_idletasks()

    def extract_features(self, url):
        # Use appropriate progress update method based on current tab
        if self.tab_control.index(self.tab_control.select()) == 0:
            self.update_single_progress(f"Extracting features for {url}...", 20)
        else:
            self.update_status(f"Extracting features for {url}...", 20)
            
        try:
            features = extract_url_features(url)
            
            # Display features in single mode
            if self.tab_control.index(self.tab_control.select()) == 0:
                self.features_text.delete(1.0, tk.END)
                self.features_text.insert(tk.END, "Extracted Features:\n\n")
                
                # Feature name mapping for display
                feature_names = {
                    'url_length': 'URL Length',
                    'has_ip': 'Contains IP',
                    'dot_count': 'Dot Count',
                    'protocol_http': 'HTTP Protocol',
                    'protocol_https': 'HTTPS Protocol',
                    'subdomain_count': 'Subdomain Count',
                    'domain_age': 'Domain Age (days)',
                    'dns_valid': 'DNS Valid',
                    'site_accessible': 'Site Accessible',
                    'has_iframe': 'Contains iFrame',
                    'has_obfuscated_script': 'Has Obfuscated Script',
                    'whois_available': 'WHOIS Available',
                    'whois_registrar': 'WHOIS Registrar',
                    'whois_registration_time': 'Registration Time',
                    'whois_expiration_time': 'Expiration Time',
                    'whois_name_server': 'Name Servers'
                }
                
                for feature, value in features.items():
                    display_name = feature_names.get(feature, feature)
                    self.features_text.insert(tk.END, f"{display_name}: {value}\n")
                
                # Update progress for single URL mode
                self.update_single_progress("Features extracted", 40)
            
            # Prepare features for prediction
            feature_list = ['url_length', 'has_ip', 'dot_count', 'protocol_http', 
                          'protocol_https', 'subdomain_count', 'domain_age', 
                          'dns_valid', 'site_accessible', 'has_iframe', 
                          'has_obfuscated_script', 'whois_available']
            
            # Build feature array
            feature_values = []
            for feature in feature_list:
                value = features.get(feature)
                if value is None:
                    value = 0 if feature != 'domain_age' else -1
                feature_values.append(float(value))
            
            return pd.DataFrame([feature_values], columns=feature_list), features
            
        except Exception as e:
            if self.tab_control.index(self.tab_control.select()) == 0:
                self.update_single_progress(f"Feature extraction failed: {str(e)}", 0)
            else:
                self.update_status(f"Feature extraction failed for {url}: {str(e)}", 0)
            return None, None

    def predict(self, features_df, url, features_dict=None, show_result=True):
        if show_result and self.tab_control.index(self.tab_control.select()) == 0:
            self.update_single_progress("Making prediction...", 60)
        elif show_result:
            self.update_status("Making prediction...", 60)
            
        try:
            if self.model is None:
                raise Exception("Model not loaded")
            
            prediction = self.model.predict(features_df)
            probability = self.model.predict_proba(features_df)
            
            # Display prediction results in single mode
            if show_result and self.tab_control.index(self.tab_control.select()) == 0:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, "Detection Result:\n\n")
                
                if prediction[0] == 1:
                    result = "⚠️ WARNING: Potential Phishing Website!"
                    self.result_text.insert(tk.END, result + "\n\n")
                else:
                    result = "✅ Legitimate Website"
                    self.result_text.insert(tk.END, result + "\n\n")
                
                self.result_text.insert(tk.END, "Confidence Analysis:\n")
                self.result_text.insert(tk.END, f"Legitimate Website Probability: {probability[0][0]:.2%}\n")
                self.result_text.insert(tk.END, f"Phishing Website Probability: {probability[0][1]:.2%}\n")
                
                # Update progress for single URL mode
                self.update_single_progress("Prediction complete", 80)
            
            # Determine key features if we have the features dictionary
            key_features = ""
            if features_dict:
                # Sort features by importance
                important_feature_keys = ['has_ip', 'protocol_https', 'dot_count', 'subdomain_count']
                important_features = []
                
                for key in important_feature_keys:
                    if key in features_dict:
                        value = features_dict[key]
                        if (key == 'has_ip' and value == 1) or \
                           (key == 'protocol_https' and value == 0) or \
                           (key == 'dot_count' and value > 3) or \
                           (key == 'subdomain_count' and value > 1):
                            important_features.append(f"{key}={value}")
                
                key_features = ", ".join(important_features)
            
            # Add to results table if in batch mode
            if not show_result:
                prediction_text = "⚠️ Phishing" if prediction[0] == 1 else "✅ Legitimate"
                confidence = f"{probability[0][1]:.2%}" if prediction[0] == 1 else f"{probability[0][0]:.2%}"
                
                self.results_table.insert('', tk.END, values=(
                    url, 
                    prediction_text, 
                    confidence, 
                    key_features
                ))
            
            return True, prediction[0], probability
            
        except Exception as e:
            if show_result and self.tab_control.index(self.tab_control.select()) == 0:
                self.update_single_progress(f"Prediction failed: {str(e)}", 0)
            else:
                self.update_status(f"Prediction failed: {str(e)}", 0)
            return False, None, None

    def start_detection(self):
        url = self.url_entry.get().strip()
        if not url:
            self.update_single_progress("Please enter a URL", 0)
            return
        
        # Disable detection button
        self.check_button.state(['disabled'])
        self.update_single_progress("Starting detection...", 10)
        
        # Reset progress
        self.single_progress_var.set(0)
        
        # Run detection in new thread
        def detection_thread():
            try:
                # Extract features
                features_df, features_dict = self.extract_features(url)
                if features_df is not None:
                    # Make prediction
                    success, prediction, probability = self.predict(features_df, url, features_dict)
                    if success:
                        result_text = "Phishing Website Detected!" if prediction == 1 else "Legitimate Website"
                        confidence = probability[0][1] if prediction == 1 else probability[0][0]
                        self.update_single_progress(f"Detection completed: {result_text} ({confidence:.2%})", 100)
                    else:
                        self.update_single_progress("Detection failed", 0)
                else:
                    self.update_single_progress("Feature extraction failed", 0)
            except Exception as e:
                self.update_single_progress(f"Detection process error: {str(e)}", 0)
            finally:
                # Re-enable detection button
                self.check_button.state(['!disabled'])
        
        threading.Thread(target=detection_thread, daemon=True).start()

    def start_batch_detection(self):
        """Process a batch of URLs from a file"""
        file_path = self.batch_file_path.get()
        if not file_path or not os.path.exists(file_path):
            # Try to get URLs from the text area
            urls = self.test_urls_text.get(1.0, tk.END).strip().split('\n')
            urls = [u.strip() for u in urls if u.strip()]
        else:
            # Load URLs from file
            urls = []
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        url = line.strip()
                        if url:
                            urls.append(url)
            except Exception as e:
                self.update_status(f"Error reading file: {str(e)}", 0)
                return
        
        if not urls:
            self.update_status("No URLs found to process", 0)
            return
        
        # Clear previous results
        for item in self.results_table.get_children():
            self.results_table.delete(item)
        
        # Reset progress indicators
        self.batch_progress_var.set(0)
        self.batch_progress_label.config(text=f"0/{len(urls)} URLs processed")
        self.results_summary.config(text="")
        
        # Disable buttons
        self.batch_check_button.state(['disabled'])
        self.quick_test_button.state(['disabled'])
        
        # Process URLs in a thread
        def batch_thread():
            success_count = 0
            phishing_count = 0
            legitimate_count = 0
            total = len(urls)
            
            self.update_status(f"Processing {total} URLs...", 0)
            
            for i, url in enumerate(urls):
                # Update both progress indicators
                self.update_batch_progress(i, total)
                
                try:
                    # Extract features
                    features_df, features_dict = self.extract_features(url)
                    if features_df is not None:
                        # Make prediction
                        success, prediction, _ = self.predict(features_df, url, features_dict, show_result=False)
                        if success:
                            success_count += 1
                            if prediction == 1:
                                phishing_count += 1
                            else:
                                legitimate_count += 1
                except Exception as e:
                    print(f"Error processing {url}: {str(e)}")
            
            # Final progress update
            self.update_batch_progress(total, total)
            
            # Update summary
            summary_text = f"Results: {phishing_count} phishing, {legitimate_count} legitimate. Success rate: {success_count}/{total} URLs."
            self.results_summary.config(text=summary_text)
            self.update_status(f"Batch processing complete. {summary_text}", 100)
            
            # Re-enable buttons
            self.batch_check_button.state(['!disabled'])
            self.quick_test_button.state(['!disabled'])
        
        threading.Thread(target=batch_thread, daemon=True).start()

    def test_example_urls(self):
        """Test the example URLs shown in the text area"""
        self.start_batch_detection()

    def export_results(self):
        """Export the batch results to a CSV file"""
        if not self.results_table.get_children():
            self.update_status("No results to export", 0)
            return
        
        # Get a filename to save to
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"phishing_detection_results_{timestamp}.csv"
        
        filename = filedialog.asksaveasfilename(
            title="Save results as",
            defaultextension=".csv",
            initialfile=default_filename,
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow(['URL', 'Prediction', 'Confidence', 'Key Features'])
                
                # Write data
                for item_id in self.results_table.get_children():
                    values = self.results_table.item(item_id, 'values')
                    writer.writerow(values)
            
            self.update_status(f"Results exported to {filename}", 100)
        except Exception as e:
            self.update_status(f"Error exporting results: {str(e)}", 0)

def main():
    root = tk.Tk()
    app = PhishingDetectorUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 