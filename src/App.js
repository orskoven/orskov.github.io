import React from 'react';
import './App.css';
import Post1 from './Post1';
import Post2 from './Post2';


const App = () => {
  return (
    <div className="container">
      <header className="header">
        <h1>Spilled Beans</h1>
        <p className="intro-text">
        </p>
      </header>
      <main className="content">
  <Post2 />
  <Post1 />
</main>
    </div>
  );
};

export default App;
