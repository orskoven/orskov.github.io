import React from 'react';
import './App.css'; // Import your CSS file

const Toolbar = () => {
  return (
    <div className="toolbar">
      <div className="toolbar-logo">
        {/* Replace with your logo or site name */}
        <span>Your Logo</span>
      </div>
      <div className="toolbar-buttons">
        {/* Add your toolbar buttons here */}
        <button className="toolbar-button">Cyber Security</button>
        <button className="toolbar-button">IT & Economics</button>
        {/* Add more buttons as needed */}
      </div>
    </div>
  );
};

export default Toolbar;
