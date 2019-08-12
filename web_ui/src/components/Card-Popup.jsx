import React, { Component } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import TextTruncate from "react-text-truncate";

import "./card-popup.scss";

import RottenTomatoeLogo from "../assets/rotten_tomatoe.svg";
import IMDbLogo from "../assets/imdb.png";

import { library } from "@fortawesome/fontawesome-svg-core";

import {
    faPlayCircle,
    faArrowCircleRight
} from "@fortawesome/free-solid-svg-icons";

library.add(
    faArrowCircleRight,
    faPlayCircle
);

class CardPopup extends Component {

    constructor(props) {
        super(props);

        this.popup = React.createRef();

        this.state = {
            styles: {
                card: {
                    left: "50%",
                    right: "unset"
                },
                clipped: {
                    clipPath: "polygon(10% 0, 100% 0, 100% 100%, 5% 100%)",
                    borderRadius: "0 1vh 1vh 0"
                },
                header: {
                    justifySelf: "end",
                    transform: "translateX(-4vh)"
                },
                content: {
                    margin: "0 4vh 0 7vh"
                }
            }
        };
    }

    componentDidMount() {
        const { x, width } = this.popup.current.getBoundingClientRect();
        const overflowing = (x + width > window.innerWidth - 100);

        if (!overflowing) return;

        this.setState({
            accent: this.props.accent,
            styles: {
                card: {
                    left: "unset",
                    right: "50%"
                },
                clipped: {
                    clipPath: "polygon(0 0, 90% 0, 95% 100%, 0% 100%)",
                    borderRadius: "1vh 0 0 1vh"
                },
                header: {
                    justifySelf: "start",
                    transform: "translateX(4vh)"
                },
                content: {
                    margin: "0 7vh 0 4vh"
                }
            }
        });

    }

    static getDerivedStateFromProps(nextProps, prevState) {
        return {
            accent: nextProps.accent,
        };
    }

    render() {
        const {
            name,
            imdb,
            rotten_tomatoes,
            description,
            genre,
            year,
            // trailer,
            length,
            play,
        } = this.props.data;

        const { accent } = this.props;

        return (
            <div className="card-popup" ref={this.popup} style={this.state.styles.card}>
                <div className="clipped" style={this.state.styles.clipped}></div>
                <section className="header" style={this.state.styles.header}>
                    <h1>{name}</h1>
                    <div className="rating">
                        <img alt="imdb" src={IMDbLogo}></img><p>{imdb}</p>
                        <img alt="rotten tomatoes" src={RottenTomatoeLogo}></img><p>{rotten_tomatoes}</p>
                    </div>
                </section>
                <section className="content" style={this.state.styles.content}>
                    <section className="description">
                        <h4>Description</h4>
                        <TextTruncate
                            text={description}
                            line={3}
                            textElement="p"
                            truncateText="..."
                        />
                    </section>
                    <section className="info">
                        <div className="tags">
                            <p style={{ background: accent}}>{genre}</p>
                            <p style={{ background: accent}}>{year}</p>
                        </div>
                        {/* <a href={trailer}><FontAwesomeIcon icon="play-circle"/>WATCH TRAILER</a> */}
                    </section>
                    <section className="separator"></section>
                    <section className="footer">
                        <div className="length">
                            <p>{length}</p>
                            <p>HH MM SS</p>
                        </div>
                        <a href={play} style={{ background: accent }}>PLAY<FontAwesomeIcon icon="arrow-alt-circle-right"/></a>
                    </section>
                </section>

            </div>
        );
    }
}

export default CardPopup;