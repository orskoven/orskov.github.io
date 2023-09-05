import React from 'react';
import './App.css';
import Post1 from './Post1';
import Post2 from './Post2';
import Post3 from './Post3';
import Toolbar from './Toolbar';


const App = () => {
  return (
    <div className="container">
      <header className="header">
        <Toolbar />
        <h1>Spilled Beans</h1>
        <p className="intro-text">
        </p>
      </header>
      <main className="content">
  <Post3 />
  <Post2 />
  <Post1 />
</main>
    </div>
  );
};

export default App;
