import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Button, Alert, Card, Form, Spinner } from 'react-bootstrap';
import { useDropzone } from 'react-dropzone';
import Papa from 'papaparse';
import axios from 'axios';
import mammoth from 'mammoth';
import fileDownload from 'js-file-download';

// We'll simplify to not use react-pdf for now

function App() {
  const [file, setFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [csvData, setCsvData] = useState(null);
  const [alert, setAlert] = useState(null);
  const [handlingMethod, setHandlingMethod] = useState('redact');
  const [scanResults, setScanResults] = useState(null);
  const [docText, setDocText] = useState('');
  const [processing, setProcessing] = useState(false);
  const [fileType, setFileType] = useState(null);
  const [processedFileType, setProcessedFileType] = useState(null);
  const [processedFileData, setProcessedFileData] = useState(null);

  // Handle file drop
  const onDrop = async (acceptedFiles) => {
    try {
      if (acceptedFiles.length === 0) return;

      const file = acceptedFiles[0];
      // Reset states
      resetStates();
      setFile(file);

      // Determine file type and set appropriate state
      const ext = file.name.split('.').pop().toLowerCase();
      setFileType(ext);

      await handleFilePreview(file, ext);
    } catch (error) {
      console.error('Error handling file:', error);
      setAlert({ type: 'danger', message: 'Error processing the uploaded file.' });
    }
  };

  const resetStates = () => {
    setFileContent('');
    setCsvData(null);
    setAlert(null);
    setScanResults(null);
    setDocText('');
    setProcessedFileData(null);
    setProcessedFileType(null);
  };

  const handleFilePreview = async (file, ext) => {
    try {
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
        // For PDFs, we'll just show a placeholder message
        setAlert({ type: 'info', message: 'PDF file uploaded. PDF content will be processed as text.' });
      } else if (['doc', 'docx'].includes(ext)) {
        if (ext === 'docx') {
          const reader = new FileReader();
          reader.onload = async (event) => {
            try {
              const result = await mammoth.extractRawText({
                arrayBuffer: event.target.result
              });
              setDocText(result.value);
            } catch (error) {
              console.error('Error processing DOCX:', error);
              setAlert({ type: 'warning', message: 'Document preview not available, but scanning will still work.' });
            }
          };
          reader.readAsArrayBuffer(file);
        } else {
          // DOC files can't be previewed directly
          setAlert({ type: 'info', message: '.doc files can be processed but not previewed.' });
        }
      } else {
        setAlert({ type: 'warning', message: 'This file type is supported for scanning but preview is not available.' });
      }
    } catch (error) {
      console.error('Error previewing file:', error);
      setAlert({ type: 'warning', message: 'Preview not available, but scanning will still work.' });
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
    if (!file) {
      setAlert({ type: 'warning', message: 'Please upload a file first.' });
      return;
    }

    setProcessing(true);
    setAlert(null);

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('handlingMethod', handlingMethod);

      const response = await axios.post('http://127.0.0.1:5000/upload', formData);

      if (response.status === 200 && response.data.status === 'success') {
        setAlert({ type: 'success', message: 'File processed successfully!' });

        // Store processed file data and type from response
        const fileType = response.data.fileType || 'txt';
        setProcessedFileType(fileType);

        // Decode base64 data
        const binaryString = atob(response.data.file);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }

        // Create appropriate blob based on file type
        let contentType = getMimeType(fileType);
        const blob = new Blob([bytes], { type: contentType });
        setProcessedFileData(blob);

        // For all file types, show as text
        const reader = new FileReader();
        reader.onload = () => setScanResults(reader.result);
        reader.readAsText(blob);
      } else {
        setAlert({ type: 'danger', message: 'Error processing the file' });
      }
    } catch (error) {
      console.error('Error uploading file:', error);
      setAlert({
        type: 'danger',
        message: error.response?.data?.message || 'Error scanning file. Please check the server connection.'
      });
    } finally {
      setProcessing(false);
    }
  };

  const downloadProcessedFile = () => {
    if (!processedFileData) return;

    let fileExt = processedFileType || 'txt';
    const fileName = `processed_${file.name.split('.')[0]}.${fileExt}`;

    fileDownload(processedFileData, fileName);
  };

  const getMimeType = (ext) => {
    const mimeTypes = {
      'pdf': 'application/pdf',
      'doc': 'application/msword',
      'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'txt': 'text/plain',
      'log': 'text/plain',
      'json': 'application/json',
      'csv': 'text/csv'
    };
    return mimeTypes[ext] || 'text/plain';
  };

  return (
    <Container fluid className="p-4">
      <Row className="justify-content-center">
        <Col md={10}>
          <Card>
            <Card.Header as="h4" className="text-center bg-primary text-white">HIPAA Document Validator</Card.Header>
            <Card.Body>
              <div
                {...getRootProps()}
                style={{
                  border: '2px dashed #007bff',
                  padding: '40px',
                  textAlign: 'center',
                  backgroundColor: '#f8f9fa',
                  borderRadius: '8px',
                  marginBottom: '20px'
                }}
              >
                <input {...getInputProps()} />
                <p><strong>Drag & drop a file here, or click to select</strong></p>
                <p><small>Supported file types: CSV, TXT, LOG, JSON, PDF, DOC, DOCX</small></p>
                <Button variant="primary">Upload File</Button>
              </div>

              {file && (
                <Alert variant="info">
                  <strong>File selected:</strong> {file.name} ({(file.size / (1024 * 1024)).toFixed(2)} MB)
                </Alert>
              )}

              <Form className="mt-4 mb-4">
                <Form.Group>
                  <Form.Label><strong>PHI Handling Method</strong></Form.Label>
                  <Row>
                    <Col md={4}>
                      <Form.Check
                        type="radio"
                        id="redact"
                        label="Redact - Replace PHI with [REDACTED]"
                        value="redact"
                        checked={handlingMethod === "redact"}
                        onChange={(e) => setHandlingMethod(e.target.value)}
                      />
                    </Col>
                    <Col md={4}>
                      <Form.Check
                        type="radio"
                        id="tokenize"
                        label="Tokenize - Replace with random tokens"
                        value="tokenize"
                        checked={handlingMethod === "tokenize"}
                        onChange={(e) => setHandlingMethod(e.target.value)}
                      />
                    </Col>
                    <Col md={4}>
                      <Form.Check
                        type="radio"
                        id="remove"
                        label="Remove - Replace with spaces"
                        value="remove"
                        checked={handlingMethod === "remove"}
                        onChange={(e) => setHandlingMethod(e.target.value)}
                      />
                    </Col>
                  </Row>
                </Form.Group>
              </Form>

              {alert && (
                <Alert variant={alert.type} className="mt-3">
                  {alert.message}
                </Alert>
              )}

              {/* File Preview Section */}
              {fileType && (
                <Card className="mt-4 mb-4">
                  <Card.Header as="h5">File Preview</Card.Header>
                  <Card.Body>
                    {csvData && (
                      <div className="preview-container" style={{ maxHeight: '300px', overflowY: 'auto' }}>
                        <table className="table table-bordered table-striped">
                          <thead>
                            <tr>{Object.keys(csvData[0] || {}).map((key) => <th key={key}>{key}</th>)}</tr>
                          </thead>
                          <tbody>
                            {csvData.slice(0, 10).map((row, i) => (
                              <tr key={i}>{Object.values(row).map((val, j) => <td key={j}>{val}</td>)}</tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}

                    {fileContent && (
                      <pre style={{ background: '#f1f1f1', padding: '1rem', borderRadius: '5px', maxHeight: '300px', overflowY: 'auto' }}>
                        {fileContent.substring(0, 3000)}
                        {fileContent.length > 3000 && "..."}
                      </pre>
                    )}

                    {docText && (
                      <div className="doc-preview">
                        <pre style={{ background: '#f1f1f1', padding: '1rem', borderRadius: '5px', maxHeight: '300px', overflowY: 'auto' }}>
                          {docText.substring(0, 3000)}
                          {docText.length > 3000 && "..."}
                        </pre>
                      </div>
                    )}

                    {['pdf', 'doc'].includes(fileType) && !docText && (
                      <Alert variant="info">
                        Preview not available for this file type, but the document can be processed for PHI detection.
                      </Alert>
                    )}
                  </Card.Body>
                  <Card.Footer>
                    <Button
                      variant="primary"
                      className="w-100"
                      onClick={handleScan}
                      disabled={processing}
                    >
                      {processing ?
                        <>
                          <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" />
                          <span className="ms-2">Processing...</span>
                        </> :
                        'Scan for PHI Violations'
                      }
                    </Button>
                  </Card.Footer>
                </Card>
              )}

              {/* Results Section */}
              {scanResults && (
                <Card className="mt-4">
                  <Card.Header as="h5">Processed Document</Card.Header>
                  <Card.Body>
                    <pre style={{ background: '#f1f1f1', padding: '1rem', borderRadius: '5px', maxHeight: '300px', overflowY: 'auto' }}>
                      {scanResults.substring(0, 3000)}
                      {scanResults.length > 3000 && "..."}
                    </pre>
                  </Card.Body>
                  <Card.Footer>
                    <Button
                      variant="success"
                      onClick={downloadProcessedFile}
                      disabled={!processedFileData}
                    >
                      Download Processed Document
                    </Button>
                  </Card.Footer>
                </Card>
              )}
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}

export default App;