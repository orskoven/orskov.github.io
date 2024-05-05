import React from 'react';
import './App.css'; // Import your CSS file

const Toolbar = () => {
  return (
    <div className="toolbar">
      <div className="toolbar-logo">
        {/* Replace with your logo or site name */}
        <span>dcpeeyhr - decrypted data/span>
      </div>
      <div className="toolbar-buttons">
        {/* Add your toolbar buttons here */}
        <a href="https://orange-rock-004fad41e-preview.westus2.5.azurestaticapps.net" className="toolbar-button">Talk with Cyber Security Assistant</a>
        <a href="https://orange-smoke-0c522e91e-preview.westus2.5.azurestaticapps.net" className="toolbar-button">Discover NIST AI.RMF</a>
        <a href="https://master.d2p1vjkxtgfh0z.amplifyapp.com" className="toolbar-button">Portfolio</a>
        {/* Add more buttons as needed */}
        <a href="https://www.youtube.com/@binarybeans" className="toolbar-button">Binary Beans YouTube</a>
      </div>
    </div>
  );
};

export default Toolbar;
