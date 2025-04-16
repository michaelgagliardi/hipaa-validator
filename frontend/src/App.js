import React, { useState } from 'react';
import { Container, Row, Col, Button, Alert, Card, Form } from 'react-bootstrap';
import { useDropzone } from 'react-dropzone';
import Papa from 'papaparse';
import axios from 'axios';
import { Document, Page } from 'react-pdf'; // For handling PDFs
import mammoth from 'mammoth'; // For handling DOC/DOCX files
import { pdfjs } from 'react-pdf';
import pdfWorker from 'pdfjs/build/pdf.worker.entry';

pdfjs.GlobalWorkerOptions.workerSrc = pdfWorker;

function App() {
  const [file, setFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [csvData, setCsvData] = useState(null);
  const [alert, setAlert] = useState(null);
  const [handlingMethod, setHandlingMethod] = useState('redact');
  const [scanResults, setScanResults] = useState(null);
  const [pdfFile, setPdfFile] = useState(null); // For PDF preview
  const [docText, setDocText] = useState(''); // For DOCX text preview

  const onDrop = (acceptedFiles) => {
    const file = acceptedFiles[0];
    setFile(file);
    setAlert(null);
    setCsvData(null);
    setFileContent('');
    setScanResults(null);
    setPdfFile(null);
    setDocText('');

    const ext = file.name.split('.').pop().toLowerCase();

    if (ext === 'csv') {
      Papa.parse(file, {
        complete: (result) => setCsvData(result.data),
        header: true,
        skipEmptyLines: true,
      });
    } else if (['txt', 'log', 'json'].includes(ext)) {
      const reader = new FileReader();
      reader.onload = () => setFileContent(reader.result);
      reader.readAsText(file);
    } else if (ext === 'pdf') {
      setPdfFile(URL.createObjectURL(file));
    } else if (['doc', 'docx'].includes(ext)) {
      const reader = new FileReader();
      reader.onload = () => {
        mammoth.extractRawText({ arrayBuffer: reader.result })
          .then((result) => setDocText(result.value))
          .catch(() => setAlert({ type: 'danger', message: 'Error processing DOC/DOCX file.' }));
      };
      reader.readAsArrayBuffer(file);
    } else {
      setAlert({ type: 'danger', message: 'Unsupported file type.' });
    }
  };

  const { getRootProps, getInputProps } = useDropzone({
    onDrop,
    accept: {
      'text/csv': ['.csv'],
      'text/plain': ['.txt', '.log'],
      'application/json': ['.json'],
      'application/pdf': ['.pdf'],
      'application/msword': ['.doc'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx']
    },
    multiple: false,
  });

  const handleScan = async () => {
    if (!file) return;

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('handlingMethod', handlingMethod);

      const response = await axios.post('http://127.0.0.1:5000/upload', formData);

      if (response.status === 200 && response.data.status === 'success') {
        setAlert({ type: 'success', message: 'File processed successfully!' });

        const byteCharacters = atob(response.data.file);
        const byteArrays = [];
        for (let offset = 0; offset < byteCharacters.length; offset += 1024) {
          const slice = byteCharacters.slice(offset, offset + 1024);
          const byteNumbers = new Array(slice.length);
          for (let i = 0; i < slice.length; i++) {
            byteNumbers[i] = slice.charCodeAt(i);
          }
          byteArrays.push(new Uint8Array(byteNumbers));
        }

        const processedBlob = new Blob(byteArrays, { type: 'application/octet-stream' });

        const reader = new FileReader();
        reader.onload = () => setScanResults(reader.result);
        reader.readAsText(processedBlob);
      } else {
        setAlert({ type: 'danger', message: 'Error processing the file' });
      }
    } catch (error) {
      console.error('Error uploading file:', error);
      setAlert({ type: 'danger', message: error.response?.data?.message || 'Error scanning file.' });
    }
  };

  return (
    <Container fluid className="p-4">
      <Row className="justify-content-center">
        <Col md={8}>
          <Card>
            <Card.Header as="h4" className="text-center">HIPAA Document Validator</Card.Header>
            <Card.Body>
              <div {...getRootProps()} style={{ border: '2px dashed #007bff', padding: '40px', textAlign: 'center' }}>
                <input {...getInputProps()} />
                <p>Drag & drop a file here, or click to select</p>
                <p><small>(.csv, .txt, .log, .json, .pdf, .doc, .docx)</small></p>
                <Button variant="primary">Upload File</Button>
              </div>

              <Form className="mt-4">
                <Form.Label><strong>PHI Handling Method</strong></Form.Label>
                <div>
                  {['redact', 'tokenize', 'remove'].map((method) => (
                    <Form.Check
                      inline
                      key={method}
                      type="radio"
                      label={method.charAt(0).toUpperCase() + method.slice(1)}
                      value={method}
                      checked={handlingMethod === method}
                      onChange={(e) => setHandlingMethod(e.target.value)}
                    />
                  ))}
                </div>
              </Form>

              {alert && (
                <Alert variant={alert.type} className="mt-3">
                  {alert.message}
                </Alert>
              )}

              {csvData && (
                <div className="mt-4">
                  <h5>CSV Data Preview:</h5>
                  <table className="table table-bordered table-striped">
                    <thead>
                      <tr>{Object.keys(csvData[0]).map((key) => <th key={key}>{key}</th>)}</tr>
                    </thead>
                    <tbody>
                      {csvData.slice(0, 10).map((row, i) => (
                        <tr key={i}>{Object.values(row).map((val, j) => <td key={j}>{val}</td>)}</tr>
                      ))}
                    </tbody>
                  </table>
                  <Button variant="success" className="mt-3" onClick={handleScan}>
                    Scan for Violations
                  </Button>
                </div>
              )}

              {fileContent && (
                <div className="mt-4">
                  <h5>Text File Preview:</h5>
                  <pre style={{ background: '#f1f1f1', padding: '1rem', borderRadius: '5px', maxHeight: '300px', overflowY: 'auto' }}>
                    {fileContent.substring(0, 3000)}
                  </pre>
                  <Button variant="success" className="mt-3" onClick={handleScan}>
                    Scan for Violations
                  </Button>
                </div>
              )}

              {pdfFile && (
                <div className="mt-4">
                  <h5>PDF Preview:</h5>
                  <Document file={pdfFile}>
                    <Page pageNumber={1} />
                  </Document>
                  <Button variant="success" className="mt-3" onClick={handleScan}>
                    Scan for Violations
                  </Button>
                </div>
              )}

              {docText && (
                <div className="mt-4">
                  <h5>DOCX Text Preview:</h5>
                  <pre style={{ background: '#f1f1f1', padding: '1rem', borderRadius: '5px', maxHeight: '300px', overflowY: 'auto' }}>
                    {docText.substring(0, 3000)}
                  </pre>
                  <Button variant="success" className="mt-3" onClick={handleScan}>
                    Scan for Violations
                  </Button>
                </div>
              )}

              {scanResults && (
                <div className="mt-4">
                  <h5>Processed File Preview:</h5>
                  {['txt', 'log', 'json', 'csv'].includes(file?.name.split('.').pop().toLowerCase()) ? (
                    <pre style={{ background: '#f1f1f1', padding: '1rem', borderRadius: '5px', maxHeight: '300px', overflowY: 'auto' }}>
                      {scanResults.substring(0, 3000)}
                    </pre>
                  ) : ['pdf'].includes(file?.name.split('.').pop().toLowerCase()) ? (
                    <Alert variant="info">This is a PDF file. Please download the result to view it.</Alert>
                  ) : ['doc', 'docx'].includes(file?.name.split('.').pop().toLowerCase()) ? (
                    <Alert variant="info">This is a Word document. Please download the result to view it.</Alert>
                  ) : (
                    <Alert variant="info">Unable to preview this file type.</Alert>
                  )}

                  <Button
                    variant="success"
                    className="mt-3"
                    onClick={() => {
                      const ext = file?.name.split('.').pop().toLowerCase();
                      const blobType =
                        ext === 'pdf' ? 'application/pdf' :
                          ext === 'doc' ? 'application/msword' :
                            ext === 'docx' ? 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' :
                              'text/plain';

                      const blob = new Blob([scanResults], { type: blobType });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `processed_file.${ext}`;
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                  >
                    Download Processed File
                  </Button>
                </div>
              )}
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}

export default App;
