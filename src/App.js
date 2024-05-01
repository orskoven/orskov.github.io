import React from 'react';
import './App.css';
import Post1 from './Post1';
import Post2 from './Post2';
import Post3 from './Post3';
import Post4 from './Post4';
import Post5 from './Post5';
import Toolbar from './Toolbar';


const App = () => {
  return (
    <div className="container">
      <header className="header">
        <Toolbar />
        <p className="intro-text">
        </p>
      </header>
      <main className="content">
            <Post5 />
    <Post4 />
  <Post3 />
  <Post2 />
  <Post1 />
</main>
    </div>
  );
};

export default App;
