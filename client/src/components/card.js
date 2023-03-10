import React ,{useState} from 'react'
import Navbar from "react-bootstrap/Navbar";
import Nav from "react-bootstrap/Nav";
import  Container  from "react-bootstrap/Container";
import { Navigate } from 'react-router-dom';
import'./card.css'


const Card = () => {
    // const isLogin = false;
    //   if(!isLogin){
    //       return <Navigate to='/login'/>;
    //   }
    const[name, setName] = useState('Anya')
    const[job, setJob] = useState('Esper')
    const[about, setAbout] = useState('Anya Forger is a character from the anime Spy x Family[1]. She has shoulder-length, light pink hair that curls inwards with a fringe that reaches just above her eyes and a small strand of ahoge at the top of her head.')

    const isLogin = localStorage.getItem('isLogin') || false;
    if(!isLogin) {
      return <Navigate to='/login'/>
    }
    return(
        <>
        <div className='bg-container'>
          <Navbar className='bg-navbar' variant="dark">
            <Container>
              <Navbar.Brand href="/home">SPBE</Navbar.Brand>
              <Nav className="me-auto">
                <Nav.Link href="/logout">Logout</Nav.Link>
              </Nav>
            </Container>
          </Navbar>
          <div className='card-container'>
            <div className='card1'>
                  <div className='upper-container'>
                      <div className='image-container'>
                          <img src='https://i.pinimg.com/736x/7d/23/f1/7d23f18d48f8509e53bb4e52f99214ce.jpg' alt='' height='100px' width='100px'></img>
                      </div>
                  </div>
                  <div className='lower-container'>
                      <h3>{name}</h3>
                      <h4>{job}</h4>
                      <p>{about}</p>
                  </div>
            </div>
          </div>
          
        </div>
        
        </>
        
    )
}

export default Card;